// QR Sync Protocol 4 Implementation
// Phases B-H of the specification.
// Reuses existing vault code (PMSETUP/PMRETRIEVE/Protocol 3a-3c).

#pragma once

#include <oqs/kem.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "auth/crypto_utils.hpp"
#include "auth/qrcodegen.hpp"
#include "auth/vault.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace auth {
namespace sync {

// Session lifetime
inline constexpr int kSessionExpirySeconds = 300;

// Identity length (>= 128 bits per spec)
inline constexpr int kIdentityBytes = 16;

// Message types for future extension
enum class MsgType : uint8_t {
  SAS = 0x01,
  APPROVAL_OD = 0x02,
  APPROVAL_ND = 0x03,
  VAULT_CHUNK = 0x04,
  VAULT_DONE = 0x05,
  ERROR_ = 0xFF
};

// QR payload structure
struct QRPayload {
  std::array<uint8_t, kIdentityBytes> id{};
  std::array<uint8_t, 1184> pk_nd{};
  std::string conn_info;
  std::chrono::system_clock::time_point expiry;
};

// SAS computation: H(PKn || ID || transcript_hash) truncated to 6 digits
inline std::string computeSAS(const std::array<uint8_t, 1184>& pk,
                              const std::array<uint8_t, kIdentityBytes>& id,
                              const std::array<uint8_t, 32>& transcript_hash) {
  std::vector<uint8_t> input;
  input.insert(input.end(), pk.begin(), pk.end());
  input.insert(input.end(), id.begin(), id.end());
  input.insert(input.end(), transcript_hash.begin(), transcript_hash.end());

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

  std::array<uint8_t, 32> hash{};
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("SHA-256 failed");
  }
  EVP_MD_CTX_free(ctx);

  // Take first 4 bytes, convert to 6-digit decimal
  uint32_t val = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                 ((uint32_t)hash[2] << 8) | hash[3];
  uint32_t truncated = val % 1000000;
  char buf[7];
  std::snprintf(buf, sizeof(buf), "%06lu", (unsigned long)truncated);
  return std::string(buf, 6);
}

// QR serialization: magic(2) + version(1) + ID(16) + PKND(1184) + connLen(2) + conn + expiry(8)
inline std::vector<uint8_t> serializeQR(const QRPayload& qr) {
  if (qr.conn_info.size() > UINT16_MAX)
    throw std::runtime_error("QR connection info is too long");
  const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
      qr.expiry.time_since_epoch()).count();
  if (epoch < 0)
    throw std::runtime_error("QR expiry predates the Unix epoch");
  std::vector<uint8_t> data;
  data.reserve(1220 + qr.conn_info.size());
  data.push_back(0x51); data.push_back(0x53);  // "QS"
  data.push_back(0x01);  // version 1
  data.insert(data.end(), qr.id.begin(), qr.id.end());
  data.insert(data.end(), qr.pk_nd.begin(), qr.pk_nd.end());
  uint16_t conn_len = static_cast<uint16_t>(qr.conn_info.size());
  data.push_back(static_cast<uint8_t>(conn_len >> 8));
  data.push_back(static_cast<uint8_t>(conn_len & 0xff));
  data.insert(data.end(), qr.conn_info.begin(), qr.conn_info.end());
  for (int i = 7; i >= 0; --i)
    data.push_back((epoch >> (static_cast<uint64_t>(i) * 8)) & 0xff);
  return data;
}

// Compact QR format for the reversed sender/receiver UI: the old device
// advertises only its endpoint and session. The new device creates its KEM
// key after scanning, so the 1184-byte public-key slot from v1 is unnecessary.
inline std::vector<uint8_t> serializeCompactQR(const QRPayload& qr) {
  if (qr.conn_info.size() > UINT16_MAX)
    throw std::runtime_error("QR connection info is too long");
  const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
      qr.expiry.time_since_epoch()).count();
  if (epoch < 0)
    throw std::runtime_error("QR expiry predates the Unix epoch");
  std::vector<uint8_t> data;
  data.reserve(31 + qr.conn_info.size());
  data.push_back(0x51); data.push_back(0x53);  // "QS"
  data.push_back(0x02);  // compact version 2
  data.insert(data.end(), qr.id.begin(), qr.id.end());
  const uint16_t conn_len = static_cast<uint16_t>(qr.conn_info.size());
  data.push_back(static_cast<uint8_t>(conn_len >> 8));
  data.push_back(static_cast<uint8_t>(conn_len & 0xff));
  data.insert(data.end(), qr.conn_info.begin(), qr.conn_info.end());
  for (int i = 7; i >= 0; --i)
    data.push_back((epoch >> (static_cast<uint64_t>(i) * 8)) & 0xff);
  return data;
}

// QR deserialization
inline QRPayload deserializeQR(const std::vector<uint8_t>& data) {
  if (data.size() < 2 || data[0] != 0x51 || data[1] != 0x53)
    throw std::runtime_error("Invalid QR magic bytes");
  if (data.size() < 3 || (data[2] != 0x01 && data[2] != 0x02))
    throw std::runtime_error("Unsupported QR version");
  const uint8_t version = data[2];

  QRPayload qr;
  size_t pos = 3;

  if (pos + kIdentityBytes > data.size()) throw std::runtime_error("Truncated QR: ID");
  std::copy(data.begin() + pos, data.begin() + pos + kIdentityBytes, qr.id.begin());
  pos += kIdentityBytes;

  if (version == 0x01) {
    if (pos + 1184 > data.size()) throw std::runtime_error("Truncated QR: PKND");
    std::copy(data.begin() + pos, data.begin() + pos + 1184, qr.pk_nd.begin());
    pos += 1184;
  }

  if (pos + 2 > data.size()) throw std::runtime_error("Truncated QR: conn len");
  uint16_t conn_len = (data[pos] << 8) | data[pos + 1];
  pos += 2;
  if (pos + conn_len > data.size()) throw std::runtime_error("Truncated QR: conn info");
  qr.conn_info.assign(data.begin() + pos, data.begin() + pos + conn_len);
  pos += conn_len;

  if (pos + 8 > data.size()) throw std::runtime_error("Truncated QR: expiry");
  uint64_t epoch = 0;
  for (int i = 0; i < 8; ++i)
    epoch = (epoch << 8) | static_cast<uint64_t>(data[pos + i]);
  pos += 8;
  if (pos != data.size()) throw std::runtime_error("Trailing data in QR payload");
  if (epoch > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
    throw std::runtime_error("QR expiry is out of range");
  qr.expiry = std::chrono::system_clock::time_point(
      std::chrono::seconds(static_cast<int64_t>(epoch)));

  return qr;
}

// KEM-based encrypt: encapsulate under target public key, then AES-GCM encrypt
// Returns: kem_ct(1088) || iv(12) || tag(16) || aead_ct
inline std::vector<uint8_t> encryptVaultForTransfer(
    const std::vector<VaultEntry>& entries,
    const std::array<uint8_t, 1184>& pk_target) {
  auto serialized = SerializeVault(entries);

  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) throw std::runtime_error("OQS_KEM_new failed");

  std::vector<uint8_t> ct(1088);
  std::vector<uint8_t> ss(32);

  if (OQS_KEM_encaps(kem, ct.data(), ss.data(),
                     pk_target.data()) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    throw std::runtime_error("OQS_KEM_encaps failed");
  }
  OQS_KEM_free(kem);

  std::vector<uint8_t> iv(12);
  if (RAND_bytes(iv.data(), 12) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("RAND_bytes failed");
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { OPENSSL_cleanse(ss.data(), ss.size()); throw std::runtime_error("EVP_CIPHER_CTX_new failed"); }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, ss.data(), iv.data()) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  OPENSSL_cleanse(ss.data(), ss.size());

  std::vector<uint8_t> ciphertext(serialized.size());
  int outlen = 0;
  if (!serialized.empty() &&
      EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                        serialized.data(), (int)serialized.size()) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptUpdate failed");
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  }

  std::vector<uint8_t> tag(16);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("GET_TAG failed");
  }
  EVP_CIPHER_CTX_free(ctx);

  std::vector<uint8_t> wire;
  wire.reserve(1088 + 12 + 16 + ciphertext.size());
  wire.insert(wire.end(), ct.begin(), ct.end());
  wire.insert(wire.end(), iv.begin(), iv.end());
  wire.insert(wire.end(), tag.begin(), tag.end());
  wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

  return wire;
}

// KEM-based decrypt: decapsulate then AES-GCM decrypt
inline std::vector<VaultEntry> decryptVaultFromTransfer(
    const std::vector<uint8_t>& wire,
    const std::array<uint8_t, 2400>& sk_target) {

  if (wire.size() < 1088 + 12 + 16)
    throw std::runtime_error("Wire too short for vault transfer");

  std::vector<uint8_t> ct(wire.begin(), wire.begin() + 1088);
  const uint8_t* iv_ptr = wire.data() + 1088;
  const uint8_t* tag_ptr = iv_ptr + 12;
  const uint8_t* ct_ptr = tag_ptr + 16;
  size_t ct_len = wire.size() - 1088 - 12 - 16;

  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) throw std::runtime_error("OQS_KEM_new failed");

  std::vector<uint8_t> ss(32);
  if (OQS_KEM_decaps(kem, ss.data(), ct.data(), sk_target.data()) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    throw std::runtime_error("OQS_KEM_decaps failed");
  }
  OQS_KEM_free(kem);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { OPENSSL_cleanse(ss.data(), ss.size()); throw std::runtime_error("EVP_CIPHER_CTX_new failed"); }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, ss.data(), iv_ptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }

  std::vector<uint8_t> plaintext(ct_len + 16);
  int outlen = 0;
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ct_ptr, (int)ct_len) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag_ptr)) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("SET_TAG failed");
  }

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &final_len) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("GCM tag verification failed");
  }
  OPENSSL_cleanse(ss.data(), ss.size());
  EVP_CIPHER_CTX_free(ctx);

  plaintext.resize(outlen + final_len);
  return DeserializeVault(plaintext);
}

// ---------------------------------------------------------------------------
// Phase H1: trust list T and session cleanup
// ---------------------------------------------------------------------------

// A device's long-term signing public key (tpm pkdev). Variable length so any
// OQS_SIG key size works. The trust list T lives inside the vault V.
using DevicePk = std::vector<uint8_t>;

// Membership check in the trust list T.
inline bool isTrustedDevice(const std::vector<DevicePk>& trust_list,
                            const DevicePk& pk) {
  return std::find(trust_list.begin(), trust_list.end(), pk) != trust_list.end();
}

// OD: T <- T U {pkND};  ND: T <- T U {pkOD}.  Idempotent.
inline void addTrustedDevice(std::vector<DevicePk>& trust_list, const DevicePk& pk) {
  if (!isTrustedDevice(trust_list, pk)) trust_list.push_back(pk);
}

// Phase I1 (revoke): T <- T \ {pk}. Returns true if the key was present.
inline bool revokeDevice(std::vector<DevicePk>& trust_list, const DevicePk& pk) {
  auto it = std::find(trust_list.begin(), trust_list.end(), pk);
  if (it == trust_list.end()) return false;
  trust_list.erase(it);
  return true;
}

// All per-session secret material (Phase B: PKn/SKn/ID/T_exp; Phase D: noise
// key; Phase E: SAS; Phase F: sigmas handled by TpmInterface; Phase G: Ks).
// Held in ND/OD memory only. wipe() must run on completion (H1) and on every
// abort path (Sec 3 failure matrix). Never logged.
struct SessionSecrets {
  std::array<uint8_t, kIdentityBytes> id{};
  std::array<uint8_t, 1184> pk_nd{};
  std::array<uint8_t, 2400> sk_nd{};
  std::vector<uint8_t> noise_key;  // handshake-derived transport key
  std::vector<uint8_t> vault_key;  // Ks from ML-KEM encapsulation (Phase G)
  std::string sas;                 // displayed only, never sent (Table IV)
  std::chrono::system_clock::time_point expiry{};
  bool used = false;               // single-use flag; replay of the QR fails

  void wipe() {
    OPENSSL_cleanse(id.data(), id.size());
    OPENSSL_cleanse(pk_nd.data(), pk_nd.size());
    OPENSSL_cleanse(sk_nd.data(), sk_nd.size());
    if (!noise_key.empty()) OPENSSL_cleanse(noise_key.data(), noise_key.size());
    if (!vault_key.empty()) OPENSSL_cleanse(vault_key.data(), vault_key.size());
    if (!sas.empty()) OPENSSL_cleanse(&sas[0], sas.size());
    noise_key.clear();
    vault_key.clear();
    sas.clear();
    expiry = std::chrono::system_clock::time_point{};
    used = false;
  }
};

// ND acceptance gate (Phase F2): ID == ID', now() < T_exp, session not already
// used. Signature verification is performed by the caller via TpmInterface.
inline bool sessionAcceptable(const SessionSecrets& session,
                              const std::array<uint8_t, kIdentityBytes>& peer_id,
                              std::chrono::system_clock::time_point now) {
  return session.id == peer_id && now < session.expiry && !session.used;
}

// Merge vault entries: keep entry with later LastModified, ensure salt consistency
inline std::vector<VaultEntry> mergeVaultEntries(
    const std::vector<VaultEntry>& local,
    const std::vector<VaultEntry>& remote) {
  std::vector<VaultEntry> result = local;
  for (const auto& rem : remote) {
    auto it = std::find_if(result.begin(), result.end(),
                           [&rem](const VaultEntry& e) {
                             return e.website == rem.website && e.username == rem.username;
                           });
    if (it == result.end()) {
      // Entry doesn't exist locally, add remote entry
      result.push_back(rem);
    } else {
      // Entry exists in both, keep the one with later LastModified
      if (rem.lastModified > it->lastModified) {
        // Remote is newer, keep remote entry
        *it = rem;
      }
      // If local is newer or equal, keep local entry (no change needed)
      // Salt consistency is maintained by keeping the winning entry's salt
    }
  }
  return result;
}

}  // namespace sync
}  // namespace auth
