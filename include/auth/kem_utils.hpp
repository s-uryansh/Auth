// ── Hybrid ML-KEM-768 + AES-256-GCM encrypt/decrypt utilities ────────────────
//
// Replaces RSA-OAEP throughout the protocol.  Each "Enc(PKs, plaintext)" call
// uses a fresh ML-KEM encapsulation so the symmetric key is never reused.
//
// Wire format produced by MlKemEncrypt:
//
//   [ kem_ct (1088 B) | iv (12 B) | gcm_tag (16 B) | aead_ct (N B) ]
//    ^                  ^            ^                ^
//    ML-KEM-768         AES-256-GCM  GCM auth tag    encrypted payload
//    ciphertext         nonce

#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/kem.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "auth/crypto_utils.hpp"
#include "auth/server_keys.hpp"

namespace auth {
namespace internal {

// Wire-format field sizes (all fixed).
inline constexpr size_t kIvBytes  = 12;  // AES-GCM recommended IV
inline constexpr size_t kTagBytes = 16;  // AES-GCM authentication tag

// Minimum overhead added to plaintext by MlKemEncrypt.
inline constexpr size_t kEncryptOverhead =
    kMlKem768CtBytes + kIvBytes + kTagBytes;

// ── MlKemEncrypt ─────────────────────────────────────────────────────────────
//
// Hybrid-encrypt |plaintext| under the server's ML-KEM-768 public key.
// Returns the wire-format ciphertext blob.
//
// Thread-safe: uses only stack/local state after reading the singleton pk.
inline std::vector<uint8_t> MlKemEncrypt(
    const std::vector<uint8_t>& plaintext) {
  // ── 1. ML-KEM encapsulation ───────────────────────────────────────────────
  OqsKemPtr kem = ServerKeys::NewKem();

  std::vector<uint8_t> kem_ct(kMlKem768CtBytes);
  // shared secret is the AES-256 key; wipe after use.
  std::vector<uint8_t> ss(kMlKem768SsBytes);

  if (OQS_KEM_encaps(kem.get(),
                     kem_ct.data(),
                     ss.data(),
                     GetServerKeys().pk()) != OQS_SUCCESS) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("OQS_KEM_encaps failed");
  }

  // ── 2. Generate random IV ─────────────────────────────────────────────────
  std::vector<uint8_t> iv(kIvBytes);
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("RAND_bytes failed generating IV");
  }

  // ── 3. AES-256-GCM encrypt ───────────────────────────────────────────────
  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                         nullptr, nullptr, nullptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_EncryptInit_ex (cipher) failed");
  }
  // Explicit IV length (redundant for 12-byte GCM but defensive).
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(kIvBytes), nullptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
  }
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                         ss.data(), iv.data()) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
  }

  // Shared secret no longer needed — wipe before any exception path.
  OPENSSL_cleanse(ss.data(), ss.size());

  std::vector<uint8_t> aead_ct(plaintext.size());
  int out_len = 0;

  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), aead_ct.data(), &out_len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");
  }

  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), aead_ct.data() + out_len,
                          &final_len) != 1)
    throw std::runtime_error("EVP_EncryptFinal_ex failed");
  (void)final_len;  // always 0 for GCM

  std::vector<uint8_t> tag(kTagBytes);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           static_cast<int>(kTagBytes),
                           tag.data()) != 1)
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");

  // ── 4. Assemble wire format: kem_ct || iv || tag || aead_ct ──────────────
  std::vector<uint8_t> result;
  result.reserve(kEncryptOverhead + aead_ct.size());
  result.insert(result.end(), kem_ct.begin(), kem_ct.end());
  result.insert(result.end(), iv.begin(),     iv.end());
  result.insert(result.end(), tag.begin(),    tag.end());
  result.insert(result.end(), aead_ct.begin(), aead_ct.end());

  return result;
}

// ── MlKemDecrypt ─────────────────────────────────────────────────────────────
//
// Decrypts a blob produced by MlKemEncrypt using the server's ML-KEM-768
// secret key.  Throws std::runtime_error on any integrity failure.
//
// Constant-time: AES-GCM tag verification is handled by OpenSSL; the
// ML-KEM decapsulation is constant-time in liboqs.
inline std::vector<uint8_t> MlKemDecrypt(
    const std::vector<uint8_t>& blob) {
  // ── 1. Parse wire format ──────────────────────────────────────────────────
  if (blob.size() < kEncryptOverhead)
    throw std::runtime_error("MlKemDecrypt: blob too short");

  const uint8_t* ptr = blob.data();

  // kem_ct: first kMlKem768CtBytes bytes
  std::vector<uint8_t> kem_ct(ptr, ptr + kMlKem768CtBytes);
  ptr += kMlKem768CtBytes;

  // iv: next kIvBytes bytes
  const uint8_t* iv_ptr = ptr;
  ptr += kIvBytes;

  // tag: next kTagBytes bytes
  std::vector<uint8_t> tag(ptr, ptr + kTagBytes);
  ptr += kTagBytes;

  // aead_ct: remainder
  const size_t aead_len = blob.size() - kEncryptOverhead;
  const uint8_t* aead_ptr = ptr;

  // ── 2. ML-KEM decapsulation → shared secret ───────────────────────────────
  OqsKemPtr kem = ServerKeys::NewKem();

  std::vector<uint8_t> ss(kMlKem768SsBytes);
  if (OQS_KEM_decaps(kem.get(),
                     ss.data(),
                     kem_ct.data(),
                     GetServerKeys().sk()) != OQS_SUCCESS) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("OQS_KEM_decaps failed");
  }

  // ── 3. AES-256-GCM decrypt + verify tag ──────────────────────────────────
  EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                         nullptr, nullptr, nullptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_DecryptInit_ex (cipher) failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(kIvBytes), nullptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
  }
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                         ss.data(), iv_ptr) != 1) {
    OPENSSL_cleanse(ss.data(), ss.size());
    throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");
  }

  OPENSSL_cleanse(ss.data(), ss.size());

  std::vector<uint8_t> plaintext(aead_len);
  int out_len = 0;

  if (aead_len > 0) {
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          aead_ptr,
                          static_cast<int>(aead_len)) != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed");
  }

  // Set expected tag before calling Final — OpenSSL requirement.
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           static_cast<int>(kTagBytes),
                           tag.data()) != 1)
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                          &final_len) != 1) {
    // Tag mismatch — wipe any partial plaintext before throwing.
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    throw std::runtime_error(
        "MlKemDecrypt: GCM tag verification failed — ciphertext tampered");
  }
  (void)final_len;

  return plaintext;
}

}  // namespace internal
}  // namespace auth