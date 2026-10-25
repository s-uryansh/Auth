#include "auth/vault.hpp"
#include "auth/crypto_utils.hpp"

#include <chrono>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

#include <limits>
#include <stdexcept>
#include <vector>

namespace auth {

// Append uint64_t in big-endian format (used for vault lastModified serialization)
void appendU64(std::vector<uint8_t>& bytes, uint64_t value) {
  bytes.push_back(static_cast<uint8_t>(value >> 56));
  bytes.push_back(static_cast<uint8_t>(value >> 48));
  bytes.push_back(static_cast<uint8_t>(value >> 40));
  bytes.push_back(static_cast<uint8_t>(value >> 32));
  bytes.push_back(static_cast<uint8_t>(value >> 24));
  bytes.push_back(static_cast<uint8_t>(value >> 16));
  bytes.push_back(static_cast<uint8_t>(value >> 8));
  bytes.push_back(static_cast<uint8_t>(value));
}

namespace {

std::vector<uint8_t> aadWithNonce(const std::vector<uint8_t>& aad,
                                  const uint8_t* nonce,
                                  size_t nonce_size) {
  if (aad.empty()) return {};
  if (aad.size() > static_cast<size_t>(std::numeric_limits<int>::max()) -
                       nonce_size) {
    throw std::runtime_error("Vault authenticated metadata is too large");
  }
  std::vector<uint8_t> result;
  result.reserve(aad.size() + nonce_size);
  result.insert(result.end(), aad.begin(), aad.end());
  result.insert(result.end(), nonce, nonce + nonce_size);
  return result;
}

class VectorWiper {
public:
  explicit VectorWiper(std::vector<uint8_t>& bytes) : bytes_(bytes) {}
  ~VectorWiper() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

  VectorWiper(const VectorWiper&) = delete;
  VectorWiper& operator=(const VectorWiper&) = delete;

private:
  std::vector<uint8_t>& bytes_;
};

}  // namespace


std::vector<uint8_t> GenerateSalt() {
  std::vector<uint8_t> salt(kSaltSize);
  if (RAND_bytes(salt.data(), static_cast<int>(kSaltSize)) != 1)
    throw std::runtime_error("RAND_bytes failed generating vault salt");
  return salt;
}

std::vector<uint8_t> DeriveKey(
    const std::vector<uint8_t>& master_password,
    const std::vector<uint8_t>& salt,
    const Argon2Params& params) {
  std::vector<uint8_t> key(params.key_length);

  int rc = argon2id_hash_raw(
      params.time_cost,
      params.memory_cost_kb,
      params.parallelism,
      master_password.data(),
      master_password.size(),
      salt.data(),
      salt.size(),
      key.data(),
      key.size());

  if (rc != ARGON2_OK) {
    OPENSSL_cleanse(key.data(), key.size());
    throw std::runtime_error(std::string("Argon2id failed: ") +
                             argon2_error_message(rc));
  }

  return key;
}

std::vector<uint8_t> EncryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<VaultEntry>& entries) {
  return EncryptVault(key, entries, {});
}

std::vector<uint8_t> EncryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<VaultEntry>& entries,
    const std::vector<uint8_t>& aad) {
  if (key.size() != 32)
    throw std::runtime_error("Vault encryption key must be 32 bytes");

  std::vector<uint8_t> plaintext = SerializeVault(entries);
  VectorWiper wipe_plaintext(plaintext);

  std::vector<uint8_t> iv(internal::kAesGcmIvBytes);
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
    throw std::runtime_error("RAND_bytes failed generating vault IV");
  const std::vector<uint8_t> authenticated_data =
      aadWithNonce(aad, iv.data(), iv.size());

  internal::EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(internal::kAesGcmIvBytes), nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }

  int aad_len = 0;
  if (!authenticated_data.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len,
                        authenticated_data.data(),
                        static_cast<int>(authenticated_data.size())) != 1) {
    throw std::runtime_error("EVP_EncryptUpdate authenticated data failed");
  }

  std::vector<uint8_t> ciphertext(plaintext.size());
  int out_len = 0;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                        plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    throw std::runtime_error("EVP_EncryptUpdate failed");
  }

  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) != 1) {
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }

  std::vector<uint8_t> tag(internal::kAesGcmTagBytes);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(internal::kAesGcmTagBytes),
                          tag.data()) != 1) {
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
  }

  // Wire format: iv (12) || tag (16) || ciphertext (N)
  std::vector<uint8_t> result;
  result.reserve(internal::kAesGcmIvBytes + internal::kAesGcmTagBytes +
                 ciphertext.size());
  result.insert(result.end(), iv.begin(), iv.end());
  result.insert(result.end(), tag.begin(), tag.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());

  return result;
}

std::vector<VaultEntry> DecryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& blob) {
  return DecryptVault(key, blob, {});
}

std::vector<VaultEntry> DecryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& blob,
    const std::vector<uint8_t>& aad) {
  if (key.size() != 32)
    throw std::runtime_error("Vault decryption key must be 32 bytes");

  constexpr size_t kVaultOverhead =
      internal::kAesGcmIvBytes + internal::kAesGcmTagBytes;
  if (blob.size() < kVaultOverhead)
    throw std::runtime_error("Vault blob too short");

  const uint8_t* iv = blob.data();
  const uint8_t* tag = blob.data() + internal::kAesGcmIvBytes;
  const uint8_t* ciphertext = blob.data() + kVaultOverhead;
  size_t ciphertext_len = blob.size() - kVaultOverhead;
  if (ciphertext_len > static_cast<size_t>(std::numeric_limits<int>::max()))
    throw std::runtime_error("Vault ciphertext is too large");
  const std::vector<uint8_t> authenticated_data =
      aadWithNonce(aad, iv, internal::kAesGcmIvBytes);

  internal::EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(internal::kAesGcmIvBytes), nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) != 1) {
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  int aad_len = 0;
  if (!authenticated_data.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len,
                        authenticated_data.data(),
                        static_cast<int>(authenticated_data.size())) != 1) {
    throw std::runtime_error("EVP_DecryptUpdate authenticated data failed");
  }

  std::vector<uint8_t> plaintext(ciphertext_len + 16);
  VectorWiper wipe_plaintext(plaintext);
  int out_len = 0;
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                        ciphertext,
                        static_cast<int>(ciphertext_len)) != 1) {
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(internal::kAesGcmTagBytes),
                          const_cast<uint8_t*>(tag)) != 1) {
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");
  }

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) != 1) {
    throw std::runtime_error("Vault decryption failed — wrong master password or tampered data");
  }

  plaintext.resize(out_len + final_len);
  return DeserializeVault(plaintext);
}

std::vector<uint8_t> SerializeVault(const std::vector<VaultEntry>& entries) {
  std::vector<uint8_t> result;

  auto append_u32 = [&result](uint32_t val) {
    result.push_back(static_cast<uint8_t>(val >> 24));
    result.push_back(static_cast<uint8_t>(val >> 16));
    result.push_back(static_cast<uint8_t>(val >> 8));
    result.push_back(static_cast<uint8_t>(val));
  };

  auto append_bytes = [&result, &append_u32](const std::vector<uint8_t>& data) {
    append_u32(static_cast<uint32_t>(data.size()));
    result.insert(result.end(), data.begin(), data.end());
  };

  append_u32(static_cast<uint32_t>(entries.size()));
  for (const auto& e : entries) {
    append_bytes({e.website.begin(), e.website.end()});
    append_bytes({e.username.begin(), e.username.end()});
    append_bytes(e.password);
    append_bytes(e.salt);
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        e.lastModified.time_since_epoch()).count();
    appendU64(result, static_cast<uint64_t>(epoch));
  }

  return result;
}

std::vector<VaultEntry> DeserializeVault(const std::vector<uint8_t>& data) {
  std::vector<VaultEntry> entries;
  size_t pos = 0;

  auto read_u32 = [&data, &pos]() -> uint32_t {
    if (pos + 4 > data.size()) throw std::runtime_error("Vault data corrupted");
    uint32_t val = (static_cast<uint32_t>(data[pos]) << 24) |
                   (static_cast<uint32_t>(data[pos + 1]) << 16) |
                   (static_cast<uint32_t>(data[pos + 2]) << 8) |
                   static_cast<uint32_t>(data[pos + 3]);
    pos += 4;
    return val;
  };

  auto read_bytes = [&data, &pos, &read_u32]() -> std::vector<uint8_t> {
    uint32_t len = read_u32();
    if (pos + len > data.size()) throw std::runtime_error("Vault data corrupted");
    std::vector<uint8_t> result(data.begin() + pos, data.begin() + pos + len);
    pos += len;
    return result;
  };

  uint32_t count = read_u32();
  constexpr size_t kMinimumEntryBytes = 5 * sizeof(uint32_t);
  if (count > (data.size() - pos) / kMinimumEntryBytes)
    throw std::runtime_error("Vault data corrupted");

  entries.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    VaultEntry e;
    auto website_bytes = read_bytes();
    auto username_bytes = read_bytes();
    e.website = std::string(website_bytes.begin(), website_bytes.end());
    e.username = std::string(username_bytes.begin(), username_bytes.end());
    e.password = read_bytes();
    e.salt = read_bytes();
    auto read_u64 = [&data, &pos]() -> uint64_t {
      if (pos + 8 > data.size()) throw std::runtime_error("Vault data corrupted");
      uint64_t val = (static_cast<uint64_t>(data[pos]) << 56) |
                     (static_cast<uint64_t>(data[pos + 1]) << 48) |
                     (static_cast<uint64_t>(data[pos + 2]) << 40) |
                     (static_cast<uint64_t>(data[pos + 3]) << 32) |
                     (static_cast<uint64_t>(data[pos + 4]) << 24) |
                     (static_cast<uint64_t>(data[pos + 5]) << 16) |
                     (static_cast<uint64_t>(data[pos + 6]) << 8) |
                     static_cast<uint64_t>(data[pos + 7]);
      pos += 8;
      return val;
    };
    uint64_t epoch = read_u64();
    e.lastModified = std::chrono::system_clock::from_time_t(epoch);
    entries.push_back(std::move(e));
  }

  if (pos != data.size())
    throw std::runtime_error("Vault data corrupted");

  return entries;
}

}  // namespace auth
