#pragma once

#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace auth::internal {

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

struct EvpPkeyDeleter {
  void operator()(EVP_PKEY* k) const noexcept { EVP_PKEY_free(k); }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* c) const noexcept { EVP_PKEY_CTX_free(c); }
};
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

}  // namespace auth::internal