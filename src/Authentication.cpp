#include "auth/Authentication.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>
#include <vector>

#include "auth/crypto_utils.hpp"
#include "auth/kem_utils.hpp"
#include "auth/server_keys.hpp"

namespace auth {

// ── ComputeClientHash ─────────────────────────────────────────────────────────
// C ← H(S ‖ P).  Password wiped immediately after.
std::vector<uint8_t> ComputeClientHash(
    const std::vector<uint8_t>& stored_salt,
    std::vector<uint8_t>& password) {
  constexpr size_t kHashSize = 32;

  internal::EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
  if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

  std::vector<uint8_t> hash_c(kHashSize);
  unsigned int hash_len = 0;

  if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx.get(), stored_salt.data(),
                       stored_salt.size()) != 1 ||
      EVP_DigestUpdate(mdctx.get(), password.data(),
                       password.size()) != 1 ||
      EVP_DigestFinal_ex(mdctx.get(), hash_c.data(), &hash_len) != 1) {
    OPENSSL_cleanse(password.data(), password.size());
    throw std::runtime_error("SHA-256 computation failed");
  }
  (void)hash_len;

  OPENSSL_cleanse(password.data(), password.size());
  return hash_c;
}

// ── VerifyOnServer ────────────────────────────────────────────────────────────
bool VerifyOnServer(
    const std::string& username,
    std::vector<uint8_t>& hash_c,
    const RegistrationPayload& server_record) {
  constexpr size_t kKeySize  = 16;
  constexpr size_t kHashSize = 32;

  // Username guard — prevents API misuse and record cross-contamination.
  if (server_record.username != username) {
    OPENSSL_cleanse(hash_c.data(), hash_c.size());
    return false;
  }

  // ── Step 1: B⊕R ← HybridDec(SKs, E) ─────────────────────────────────────
  std::vector<uint8_t> b_xor_r =
      internal::MlKemDecrypt(server_record.encrypted_secret_e);

  if (b_xor_r.size() != kKeySize) {
    OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());
    OPENSSL_cleanse(hash_c.data(),  hash_c.size());
    throw std::runtime_error("Decrypted B⊕R has unexpected length");
  }

  // ── Step 2: B = (B⊕R) ⊕ R ───────────────────────────────────────────────
  if (server_record.server_nonce_r.size() != kKeySize) {
    OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());
    OPENSSL_cleanse(hash_c.data(),  hash_c.size());
    throw std::runtime_error("server_nonce_r has unexpected length");
  }

  std::vector<uint8_t> secret_b(kKeySize);
  internal::XorBytes(b_xor_r, server_record.server_nonce_r, secret_b);
  OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());

  // ── Step 3: D ← HybridDec(SKs, ED) ──────────────────────────────────────
  std::vector<uint8_t> original_d =
      internal::MlKemDecrypt(server_record.encrypted_verifier_ed);

  // ── Step 4: D' ← HMAC_B(C) ───────────────────────────────────────────────
  std::vector<uint8_t> recomputed_d(kHashSize);
  unsigned int hmac_len = 0;
  bool is_authenticated = false;

  if (HMAC(EVP_sha256(),
           secret_b.data(), static_cast<int>(secret_b.size()),
           hash_c.data(),   static_cast<int>(hash_c.size()),
           recomputed_d.data(), &hmac_len) != nullptr) {
    (void)hmac_len;
    // ── Step 5: D == D'? constant-time comparison ─────────────────────────
    if (original_d.size() == kHashSize &&
        CRYPTO_memcmp(original_d.data(), recomputed_d.data(), kHashSize) == 0)
      is_authenticated = true;
  }

  // Wipe every sensitive intermediate before returning.
  OPENSSL_cleanse(hash_c.data(),      hash_c.size());
  OPENSSL_cleanse(secret_b.data(),    secret_b.size());
  OPENSSL_cleanse(original_d.data(),  original_d.size());
  OPENSSL_cleanse(recomputed_d.data(), kHashSize);

  return is_authenticated;
}

// ── AuthenticateUser ──────────────────────────────────────────────────────────
bool AuthenticateUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& stored_salt,
    const RegistrationPayload& server_record) {
  std::vector<uint8_t> hash_c = ComputeClientHash(stored_salt, password);
  return VerifyOnServer(username, hash_c, server_record);
}

}  // namespace auth