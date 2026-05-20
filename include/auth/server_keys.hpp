#pragma once

#include <oqs/kem.h>
#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace auth {
namespace internal {

// ML-KEM-768 parameter set (NIST FIPS 203, security category 2).
// All sizes are fixed constants from the standard.
inline constexpr size_t kMlKem768PkBytes  = 1184;  // public key
inline constexpr size_t kMlKem768SkBytes  = 2400;  // secret key
inline constexpr size_t kMlKem768CtBytes  = 1088;  // KEM ciphertext
inline constexpr size_t kMlKem768SsBytes  = 32;    // shared secret

// ── OQS_KEM RAII wrapper ──────────────────────────────────────────────────────

struct OqsKemDeleter {
  void operator()(OQS_KEM* k) const noexcept { OQS_KEM_free(k); }
};
using OqsKemPtr = std::unique_ptr<OQS_KEM, OqsKemDeleter>;

// ── ServerKeys — singleton holding an ML-KEM-768 keypair ─────────────────────
//
// In a real deployment the secret key never leaves the server HSM;
// here both sides share the same process for protocol simulation.
//
// Keys are generated once on first access (Meyers singleton, thread-safe
// since C++11 guarantees static-local initialization is atomic).
class ServerKeys {
 public:
  static ServerKeys& Instance() {
    static ServerKeys instance;
    return instance;
  }

  // Raw pointer to public key bytes (kMlKem768PkBytes).
  const uint8_t* pk() const noexcept { return pk_.data(); }

  // Raw pointer to secret key bytes (kMlKem768SkBytes).
  // Access is intentionally restricted to the server-side decrypt path.
  const uint8_t* sk() const noexcept { return sk_.data(); }

  // Convenience: a fresh OQS_KEM handle for the ML-KEM-768 algorithm.
  // Caller owns the returned pointer via OqsKemPtr.
  static OqsKemPtr NewKem() {
    OqsKemPtr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768));
    if (!kem)
      throw std::runtime_error("OQS_KEM_new(ML-KEM-768) failed — "
                               "liboqs built without ML-KEM support");
    return kem;
  }

  // Non-copyable, non-movable singleton.
  ServerKeys(const ServerKeys&)            = delete;
  ServerKeys& operator=(const ServerKeys&) = delete;
  ServerKeys(ServerKeys&&)                 = delete;
  ServerKeys& operator=(ServerKeys&&)      = delete;

  ~ServerKeys() {
    // Wipe secret key material before deallocation.
    OPENSSL_cleanse(sk_.data(), sk_.size());
  }

 private:
  ServerKeys() {
    OqsKemPtr kem = NewKem();

    if (OQS_KEM_keypair(kem.get(), pk_.data(), sk_.data()) != OQS_SUCCESS)
      throw std::runtime_error("OQS_KEM_keypair failed");
  }

  // Fixed-size arrays avoid heap fragmentation and simplify cleansing.
  std::array<uint8_t, kMlKem768PkBytes> pk_{};
  std::array<uint8_t, kMlKem768SkBytes> sk_{};
};

inline ServerKeys& GetServerKeys() { return ServerKeys::Instance(); }

}  // namespace internal
}  // namespace auth