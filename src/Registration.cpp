#include "auth/Registration.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <vector>

#include "auth/crypto_utils.hpp"
#include "auth/kem_utils.hpp"
#include "auth/server_keys.hpp"

namespace auth {

namespace {

// Shared registration core.
// Precondition: server_r.size() == 16.
RegistrationPayload RegisterUserImpl(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& server_r,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db) {
  constexpr size_t kKeySize  = 16;  // 128-bit S and B
  constexpr size_t kHashSize = 32;  // SHA-256 output

  // ── Step 1: S, B ←$ {0,1}^128 ────────────────────────────────────────────
  std::vector<uint8_t> salt_s(kKeySize);
  std::vector<uint8_t> secret_b(kKeySize);
  if (RAND_bytes(salt_s.data(), static_cast<int>(kKeySize)) != 1 ||
      RAND_bytes(secret_b.data(), static_cast<int>(kKeySize)) != 1)
    throw std::runtime_error("CSPRNG generation failed");

  // ── Step 2: B⊕R ──────────────────────────────────────────────────────────
  std::vector<uint8_t> b_xor_r(kKeySize);
  internal::XorBytes(secret_b, server_r, b_xor_r);

  // ── Step 3: E ← HybridEnc(PKs, B⊕R)  [ML-KEM-768 + AES-256-GCM] ────────
  const std::vector<uint8_t> encrypted_e =
      internal::MlKemEncrypt(b_xor_r);
  OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());

  // ── Step 4: C ← H(S ‖ P) ─────────────────────────────────────────────────
  internal::EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
  if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

  std::vector<uint8_t> hash_c(kHashSize);
  unsigned int hash_len = 0;
  if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx.get(), salt_s.data(),
                       static_cast<int>(kKeySize)) != 1 ||
      EVP_DigestUpdate(mdctx.get(), password.data(),
                       static_cast<int>(password.size())) != 1 ||
      EVP_DigestFinal_ex(mdctx.get(), hash_c.data(), &hash_len) != 1)
    throw std::runtime_error("SHA-256 computation failed");
  (void)hash_len;

  // ── Step 5: D ← HMAC_B(C) ────────────────────────────────────────────────
  std::vector<uint8_t> verifier_d(kHashSize);
  unsigned int hmac_len = 0;
  if (HMAC(EVP_sha256(),
           secret_b.data(), static_cast<int>(secret_b.size()),
           hash_c.data(),   static_cast<int>(hash_c.size()),
           verifier_d.data(), &hmac_len) == nullptr)
    throw std::runtime_error("HMAC computation failed");
  (void)hmac_len;

  // ── Step 6: ED ← HybridEnc(PKs, D)  [ML-KEM-768 + AES-256-GCM] ─────────
  const std::vector<uint8_t> encrypted_ed =
      internal::MlKemEncrypt(verifier_d);

  // ── Step 7: Store S locally; wipe all plaintext intermediates ─────────────
  local_db[username] = salt_s;

  OPENSSL_cleanse(password.data(),    password.size());
  OPENSSL_cleanse(secret_b.data(),    secret_b.size());
  OPENSSL_cleanse(hash_c.data(),      kHashSize);
  OPENSSL_cleanse(verifier_d.data(),  kHashSize);

  return {username, encrypted_e, encrypted_ed, server_r};
}

}  // namespace

// ── Public overload 1: explicit server nonce ──────────────────────────────────
auto RegisterUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& server_r,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload {
  if (server_r.size() != 16)
    throw std::runtime_error("server_r must be exactly 16 bytes");
  return RegisterUserImpl(username, password, server_r, local_db);
}

// ── Public overload 2: internally-generated R ─────────────────────────────────
auto RegisterUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload {
  std::vector<uint8_t> r(16);
  if (RAND_bytes(r.data(), 16) != 1)
    throw std::runtime_error("CSPRNG failed generating server nonce R");
  return RegisterUserImpl(username, password, r, local_db);
}

}  // namespace auth