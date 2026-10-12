#include "auth/vault.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace auth {

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
  std::vector<uint8_t> plaintext = SerializeVault(entries);

  std::vector<uint8_t> iv(12);
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
    throw std::runtime_error("RAND_bytes failed generating vault IV");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }

  std::vector<uint8_t> ciphertext(plaintext.size());
  int out_len = 0;
  if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                        plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptUpdate failed");
  }

  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }

  std::vector<uint8_t> tag(16);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
  }
  EVP_CIPHER_CTX_free(ctx);

  // Wire format: iv (12) || tag (16) || ciphertext (N)
  std::vector<uint8_t> result;
  result.reserve(12 + 16 + ciphertext.size());
  result.insert(result.end(), iv.begin(), iv.end());
  result.insert(result.end(), tag.begin(), tag.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());

  OPENSSL_cleanse(plaintext.data(), plaintext.size());
  return result;
}

std::vector<VaultEntry> DecryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& blob) {
  if (blob.size() < 28)  // iv(12) + tag(16) minimum
    throw std::runtime_error("Vault blob too short");

  const uint8_t* iv = blob.data();
  const uint8_t* tag = blob.data() + 12;
  const uint8_t* ciphertext = blob.data() + 28;
  size_t ciphertext_len = blob.size() - 28;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  std::vector<uint8_t> plaintext(ciphertext_len);
  int out_len = 0;
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                        ciphertext,
                        static_cast<int>(ciphertext_len)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                          const_cast<uint8_t*>(tag)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");
  }

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Vault decryption failed — wrong master password or tampered data");
  }
  EVP_CIPHER_CTX_free(ctx);

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
  entries.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    VaultEntry e;
    auto website_bytes = read_bytes();
    auto username_bytes = read_bytes();
    e.website = std::string(website_bytes.begin(), website_bytes.end());
    e.username = std::string(username_bytes.begin(), username_bytes.end());
    e.password = read_bytes();
    e.salt = read_bytes();
    entries.push_back(std::move(e));
  }

  return entries;
}

}  // namespace auth
