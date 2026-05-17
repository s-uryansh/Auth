#pragma once

#include <openssl/evp.h>

#include <memory>

namespace auth {
namespace internal {

// RAII deleters for OpenSSL context types.
struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};

struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const noexcept {
    EVP_PKEY_CTX_free(ctx);
  }
};

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

// XOR two equal-length byte vectors; result written into |out|.
// |out| must be pre-sized to match |a| and |b|.
inline void XorBytes(const std::vector<uint8_t>& a,
                     const std::vector<uint8_t>& b,
                     std::vector<uint8_t>& out) {
  for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
}

}  // namespace internal
}  // namespace auth