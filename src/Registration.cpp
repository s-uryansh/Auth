#include "auth/Registration.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <vector>

#include "auth/crypto_utils.hpp"
#include "auth/server_keys.hpp"

namespace auth {

namespace {

// Protocol 1, step 3/6: E <- Enc(PKs, B), ED <- Enc(PKs, D)
// RSA-OAEP with SHA-256. PKs = server public key.
std::vector<uint8_t> EncryptWithServerPubKey(const std::vector<uint8_t>& plaintext) {
  EVP_PKEY* pub = internal::GetServerKeys().pub();

  internal::EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(pub, nullptr));
  if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

  if (EVP_PKEY_encrypt_init(ctx.get()) != 1) throw std::runtime_error("EVP_PKEY_encrypt_init failed");

  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1) throw std::runtime_error("set_rsa_padding failed");
  
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) != 1) throw std::runtime_error("set_rsa_oaep_md failed");

  // Determine ciphertext length
  size_t outlen = 0;
  if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, plaintext.data(), plaintext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_encrypt (size) failed");

  std::vector<uint8_t> ciphertext(outlen);
  if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) != 1)
    throw std::runtime_error("EVP_PKEY_encrypt failed");

  ciphertext.resize(outlen);
  return ciphertext;
}

}  // namespace

// Protocol 1 (Registration): generates S, B; computes E, C, D, ED;
// stores S in local_db; transmits {U, E, ED} as RegistrationPayload.
auto RegisterUser(
    const std::string& username, std::vector<uint8_t>& password,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db
    ) -> RegistrationPayload {
      
  const size_t kKeySize  = 16;  // 128-bit S and B
  const size_t kHashSize = 32;  // SHA-256 output

  // Step 1: S, B <- {0,1}^128
  std::vector<uint8_t> salt_s(kKeySize);
  std::vector<uint8_t> secret_b(kKeySize);
  if (RAND_bytes(salt_s.data(), static_cast<int>(salt_s.size())) != 1 ||
      RAND_bytes(secret_b.data(), static_cast<int>(secret_b.size())) != 1)
    throw std::runtime_error("CSPRNG generation failed");

  // E <- Enc(PKs, B)
  const std::vector<uint8_t> encrypted_b = EncryptWithServerPubKey(secret_b);

  // C <- H(S, P)
  internal::EvpMdCtxPtr mdctx(EVP_MD_CTX_new());
  if (!mdctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

  std::vector<uint8_t> hash_c(kHashSize);
  unsigned int hash_len = 0;
  if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(mdctx.get(), salt_s.data(),
                       static_cast<int>(salt_s.size())) != 1 ||
      EVP_DigestUpdate(mdctx.get(), password.data(),
                       static_cast<int>(password.size())) != 1 ||
      EVP_DigestFinal_ex(mdctx.get(), hash_c.data(), &hash_len) != 1)
    throw std::runtime_error("SHA-256 computation failed");

  // D <- HMAC_B(C)
  std::vector<uint8_t> verifier_d(kHashSize);
  unsigned int hmac_len = 0;
  if (HMAC(EVP_sha256(), secret_b.data(), static_cast<int>(secret_b.size()),
           hash_c.data(), hash_c.size(), verifier_d.data(),
           &hmac_len) == nullptr)
    throw std::runtime_error("HMAC computation failed");

  // ED <- Enc(PKs, D)
  const std::vector<uint8_t> encrypted_d = EncryptWithServerPubKey(verifier_d);

  // Store S locally; delete all plaintext intermediates
  local_db[username] = salt_s;

  OPENSSL_cleanse(password.data(), password.size());
  OPENSSL_cleanse(secret_b.data(), secret_b.size());
  OPENSSL_cleanse(hash_c.data(), kHashSize);
  OPENSSL_cleanse(verifier_d.data(), kHashSize);

  return {username, encrypted_b, encrypted_d};
}

}  // namespace auth