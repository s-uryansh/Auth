#include "auth/Authentication.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>
#include <vector>

#include "auth/crypto_utils.hpp"
#include "auth/server_keys.hpp"

namespace auth {

namespace {

// RSA-OAEP/SHA-256 decryption with the server's private key.
// Used to decrypt both E → B⊕R  and  ED → D.
std::vector<uint8_t> DecryptWithServerPrivKey(
    const std::vector<uint8_t>& ciphertext) {
  EVP_PKEY* priv = internal::GetServerKeys().priv();

  internal::EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv, nullptr));
  if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");
  if (EVP_PKEY_decrypt_init(ctx.get()) != 1)
    throw std::runtime_error("EVP_PKEY_decrypt_init failed");
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1)
    throw std::runtime_error("set_rsa_padding failed");
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1)
    throw std::runtime_error("set_rsa_oaep_md failed");

  // First call: determine plaintext length.
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ciphertext.data(),
                       ciphertext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_decrypt (size query) failed");

  std::vector<uint8_t> plaintext(outlen);
  if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outlen, ciphertext.data(),
                       ciphertext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_decrypt failed");

  plaintext.resize(outlen);
  return plaintext;
}

}  // namespace

// Protocol 2 — client side.
// C ← H(S, P).  Wipes P immediately after.
std::vector<uint8_t> ComputeClientHash(const std::vector<uint8_t>& stored_salt,
                                       std::vector<uint8_t>& password) {
  const size_t kHashSize = 32;

  internal::EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
  if (!mdctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

  std::vector<uint8_t> hash_c(kHashSize);
  unsigned int hash_len = 0;

  if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx.get(), stored_salt.data(),
                       stored_salt.size()) != 1 ||
      EVP_DigestUpdate(mdctx.get(), password.data(), password.size()) != 1 ||
      EVP_DigestFinal_ex(mdctx.get(), hash_c.data(), &hash_len) != 1) {
    OPENSSL_cleanse(password.data(), password.size());
    throw std::runtime_error("SHA-256 computation failed");
  }

  OPENSSL_cleanse(password.data(), password.size());
  return hash_c;
}

// Protocol 2 — server side (updated).
//
// Key change from original protocol:
//   Old: Dec(SKs, E) → B  directly.
//   New: Dec(SKs, E) → B⊕R,  then  B = (B⊕R) ⊕ R
//        where R is the server nonce stored in server_record.server_nonce_r.
//
// This means an attacker who only has E (from the server DB) and C
// (from the user DB) cannot recover B without also knowing R, which is
// stored exclusively on the server and never transmitted to the user device.
bool VerifyOnServer(const std::string& username, std::vector<uint8_t>& hash_c,
                    const RegistrationPayload& server_record) {
  const size_t kKeySize = 16;
  const size_t kHashSize = 32;

  // Username check prevents API misuse / record mix-up.
  if (server_record.username != username) {
    OPENSSL_cleanse(hash_c.data(), kHashSize);
    return false;
  }

  // ── Step 1: B⊕R ← Dec(SKs, E) ─────────────────────────────────────────
  std::vector<uint8_t> b_xor_r =
      DecryptWithServerPrivKey(server_record.encrypted_secret_e);

  if (b_xor_r.size() != kKeySize) {
    OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());
    OPENSSL_cleanse(hash_c.data(), kHashSize);
    throw std::runtime_error("Decrypted B⊕R has unexpected length");
  }

  // ── Step 2: B = (B⊕R) ⊕ R ─────────────────────────────────────────────
  // Recover the original secret B by XORing with the stored server nonce R.
  if (server_record.server_nonce_r.size() != kKeySize) {
    OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());
    OPENSSL_cleanse(hash_c.data(), kHashSize);
    throw std::runtime_error("server_nonce_r has unexpected length");
  }

  std::vector<uint8_t> secret_b(kKeySize);
  internal::XorBytes(b_xor_r, server_record.server_nonce_r, secret_b);
  OPENSSL_cleanse(b_xor_r.data(), b_xor_r.size());  // wipe B⊕R immediately

  // ── Step 3: D ← Dec(SKs, ED) ───────────────────────────────────────────
  std::vector<uint8_t> original_verifier_d =
      DecryptWithServerPrivKey(server_record.encrypted_verifier_ed);

  // ── Step 4: D' ← HMAC_B(C) ─────────────────────────────────────────────
  std::vector<uint8_t> recomputed_verifier_d(kHashSize);
  unsigned int hmac_len = 0;

  bool is_authenticated = false;

  if (HMAC(EVP_sha256(), secret_b.data(), secret_b.size(), hash_c.data(),
           hash_c.size(), recomputed_verifier_d.data(),
           &hmac_len) != nullptr) {
    // ── Step 5: D == D'? (constant-time) ───────────────────────────────
    if (original_verifier_d.size() == recomputed_verifier_d.size() &&
        CRYPTO_memcmp(original_verifier_d.data(), recomputed_verifier_d.data(),
                      kHashSize) == 0)
      is_authenticated = true;
  }

  // Wipe all sensitive intermediates before returning.
  OPENSSL_cleanse(hash_c.data(), kHashSize);
  OPENSSL_cleanse(secret_b.data(), secret_b.size());
  OPENSSL_cleanse(original_verifier_d.data(), original_verifier_d.size());
  OPENSSL_cleanse(recomputed_verifier_d.data(), kHashSize);

  return is_authenticated;
}

// Convenience wrapper: client hash + server verify in one call.
bool AuthenticateUser(const std::string& username,
                      std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& stored_salt,
                      const RegistrationPayload& server_record) {
  std::vector<uint8_t> hash_c = ComputeClientHash(stored_salt, password);
  return VerifyOnServer(username, hash_c, server_record);
}

}  // namespace auth