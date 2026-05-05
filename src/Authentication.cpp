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

// Protocol 2, step 4/5: B <- Dec(SKs, E), D <- Dec(SKs, ED)
// RSA-OAEP with SHA-256. SKs = server private key.
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

  // Determine plaintext length
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen,
                       ciphertext.data(), ciphertext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_decrypt (size) failed");

  std::vector<uint8_t> plaintext(outlen);
  if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outlen,
                       ciphertext.data(), ciphertext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_decrypt failed");

  plaintext.resize(outlen);
  return plaintext;
}

}  // namespace

// Protocol 2, client side: C <- H(S, P). Wipes P immediately after.
std::vector<uint8_t> ComputeClientHash(const std::vector<uint8_t>& stored_salt,
                                       std::vector<uint8_t>& password) {
  const size_t kHashSize = 32;

  internal::EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
  if (!mdctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

  std::vector<uint8_t> hash_c(kHashSize);
  unsigned int hash_len = 0;

  if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx.get(), stored_salt.data(), stored_salt.size()) != 1 ||
      EVP_DigestUpdate(mdctx.get(), password.data(), password.size()) != 1 ||
      EVP_DigestFinal_ex(mdctx.get(), hash_c.data(), &hash_len) != 1) {
    OPENSSL_cleanse(password.data(), password.size());
    throw std::runtime_error("SHA-256 computation failed");
  }

  OPENSSL_cleanse(password.data(), password.size());
  return hash_c;
}

// Protocol 2, server side: decrypts E->B and ED->D, recomputes D'=HMAC_B(C),
// returns D == D'. Username check prevents API misuse.
bool VerifyOnServer(const std::string& username,
                    std::vector<uint8_t>& hash_c,
                    const RegistrationPayload& server_record) {
  const size_t kHashSize = 32;

  if (server_record.username != username) {
    OPENSSL_cleanse(hash_c.data(), kHashSize);
    return false;
  }

  // B <- Dec(SKs, E)
  std::vector<uint8_t> secret_b =
      DecryptWithServerPrivKey(server_record.encrypted_secret_e);

  // D <- Dec(SKs, ED)
  std::vector<uint8_t> original_verifier_d =
      DecryptWithServerPrivKey(server_record.encrypted_verifier_ed);

  // D' <- HMAC_B(C)
  std::vector<uint8_t> new_verifier_d_prime(kHashSize);
  unsigned int hmac_len = 0;

  bool is_authenticated = false;

  if (HMAC(EVP_sha256(), secret_b.data(), secret_b.size(),
           hash_c.data(), hash_c.size(),
           new_verifier_d_prime.data(), &hmac_len) != nullptr) {
    // Constant-time compare prevents timing attacks
    if (original_verifier_d.size() == new_verifier_d_prime.size() &&
        CRYPTO_memcmp(original_verifier_d.data(),
                      new_verifier_d_prime.data(), kHashSize) == 0)
      is_authenticated = true;
  }

  OPENSSL_cleanse(hash_c.data(), kHashSize);
  OPENSSL_cleanse(secret_b.data(), secret_b.size());
  OPENSSL_cleanse(original_verifier_d.data(), kHashSize);
  OPENSSL_cleanse(new_verifier_d_prime.data(), kHashSize);

  return is_authenticated;
}

// Convenience wrapper: client hash + server verify in one call
bool AuthenticateUser(const std::string& username,
                      std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& stored_salt,
                      const RegistrationPayload& server_record) {
  std::vector<uint8_t> hash_c = ComputeClientHash(stored_salt, password);
  return VerifyOnServer(username, hash_c, server_record);
}

}  // namespace auth