#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdexcept>

#include "auth/crypto_utils.hpp"

namespace auth::internal {

// RSA-2048 keypair. In production these would be loaded from secure storage.
// GenerateServerKeys() must be called once before Register/Authenticate.
struct ServerKeys {
  EvpPkeyPtr keypair;  // holds both public and private key

  EVP_PKEY* pub() const { return keypair.get(); }
  EVP_PKEY* priv() const { return keypair.get(); }
};

inline ServerKeys& GetServerKeys() {
  static ServerKeys keys = []() {
    ServerKeys sk;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx)
      throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
      throw std::runtime_error("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1)
      throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
      throw std::runtime_error("EVP_PKEY_keygen failed");

    sk.keypair.reset(raw);
    return sk;
  }();
  return keys;
}

}  // namespace auth::internal