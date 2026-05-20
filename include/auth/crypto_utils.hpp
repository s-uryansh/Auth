#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace auth {
namespace internal {

// ── OpenSSL RAII wrappers ─────────────────────────────────────────────────────

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};

struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
    EVP_CIPHER_CTX_free(ctx);
  }
};

struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* ctx) const noexcept {
    EVP_PKEY_CTX_free(ctx);
  }
};

using EvpMdCtxPtr     = std::unique_ptr<EVP_MD_CTX,     EvpMdCtxDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EvpPkeyCtxPtr   = std::unique_ptr<EVP_PKEY_CTX,   EvpPkeyCtxDeleter>;

// ── Byte utilities ────────────────────────────────────────────────────────────

// XOR two equal-length byte vectors; result written into |out|.
// Precondition: a.size() == b.size() == out.size().
inline void XorBytes(const std::vector<uint8_t>& a,
                     const std::vector<uint8_t>& b,
                     std::vector<uint8_t>& out) {
  for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
}

}  // namespace internal
}  // namespace auth