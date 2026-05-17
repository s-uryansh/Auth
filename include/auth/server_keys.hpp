#pragma once

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>

namespace auth {
namespace internal {

// Singleton holder for the server's RSA-OAEP keypair.
// In a real deployment the private key would never reside on the
// user device; here both sides share the same process for testing.
class ServerKeys {
 public:
  static ServerKeys& Instance() {
    static ServerKeys instance;
    return instance;
  }

  EVP_PKEY* pub() const noexcept { return pkey_.get(); }
  EVP_PKEY* priv() const noexcept { return pkey_.get(); }

 private:
  struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* k) const noexcept { EVP_PKEY_free(k); }
  };
  using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

  ServerKeys() {
    // Generate a 2048-bit RSA key for the demo.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("set_rsa_keygen_bits failed");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &raw) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);
    pkey_ = EvpPkeyPtr(raw);
  }

  EvpPkeyPtr pkey_;
};

inline ServerKeys& GetServerKeys() { return ServerKeys::Instance(); }

}  // namespace internal
}  // namespace auth