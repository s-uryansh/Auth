// Experimental ML-KEM handshake helpers for QR sync.
//
// This is a KEM key exchange with transcript-bound key derivation, not an
// implementation of the standardized Noise NK pattern. Do not treat the name
// or these helpers as evidence of production Noise security.

#pragma once

#include <oqs/kem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace auth {
namespace internal {

inline constexpr size_t kHandshakeSecretBytes = 32;
inline constexpr size_t kMlKem768HandshakePkBytes = 1184;
inline constexpr size_t kMlKem768HandshakeSkBytes = 2400;
inline constexpr size_t kMlKem768HandshakeCtBytes = 1088;

struct HandshakeState {
  std::vector<uint8_t> transcript;
  std::vector<uint8_t> kem_ciphertext;
  std::array<uint8_t, kHandshakeSecretBytes> shared_secret{};
  std::array<uint8_t, kHandshakeSecretBytes> noise_key{};

  void wipe() noexcept {
    if (!shared_secret.empty()) OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    if (!noise_key.empty()) OPENSSL_cleanse(noise_key.data(), noise_key.size());
    if (!kem_ciphertext.empty()) OPENSSL_cleanse(kem_ciphertext.data(), kem_ciphertext.size());
    if (!transcript.empty()) OPENSSL_cleanse(transcript.data(), transcript.size());
    shared_secret.fill(0);
    noise_key.fill(0);
    kem_ciphertext.clear();
    transcript.clear();
  }
};

inline std::array<uint8_t, kHandshakeSecretBytes> sha256(
    const uint8_t* data, size_t len) {
  std::array<uint8_t, kHandshakeSecretBytes> out{};
  unsigned int out_len = 0;
  if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr) != 1 ||
      out_len != out.size())
    throw std::runtime_error("SHA-256 failed");
  return out;
}

inline std::array<uint8_t, kHandshakeSecretBytes> hmac256(
    const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
  std::array<uint8_t, kHandshakeSecretBytes> out{};
  unsigned int out_len = 0;
  if (key_len > static_cast<size_t>(INT_MAX) ||
      !HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, data_len,
            out.data(), &out_len) || out_len != out.size())
    throw std::runtime_error("HMAC-SHA256 failed");
  return out;
}

inline void deriveHandshakeKeys(HandshakeState& state,
                                std::vector<uint8_t>& kem_secret) {
  auto transcript_hash = sha256(state.transcript.data(), state.transcript.size());
  std::vector<uint8_t> ikm(kem_secret);
  ikm.insert(ikm.end(), transcript_hash.begin(), transcript_hash.end());
  auto shared = sha256(ikm.data(), ikm.size());
  std::copy(shared.begin(), shared.end(), state.shared_secret.begin());
  auto key = hmac256(state.shared_secret.data(), state.shared_secret.size(),
                     state.transcript.data(), state.transcript.size());
  std::copy(key.begin(), key.end(), state.noise_key.begin());
  OPENSSL_cleanse(ikm.data(), ikm.size());
  OPENSSL_cleanse(kem_secret.data(), kem_secret.size());
}

// Old device (initiator): encapsulate to the new device's QR public key.
// out_wire contains the ML-KEM ciphertext. Only the ND can recover this secret.
inline HandshakeState odHandshakeInit(const std::vector<uint8_t>& pk_nd,
                                      std::vector<uint8_t>& out_wire) {
  OQS_KEM* raw_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!raw_kem) throw std::runtime_error("ML-KEM-768 unavailable");
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem(raw_kem, &OQS_KEM_free);
  if (pk_nd.size() != kem->length_public_key)
    throw std::runtime_error("Invalid ML-KEM-768 public key length");

  HandshakeState state;
  std::vector<uint8_t> secret(kem->length_shared_secret);
  state.kem_ciphertext.resize(kem->length_ciphertext);
  if (OQS_KEM_encaps(kem.get(), state.kem_ciphertext.data(), secret.data(),
                     pk_nd.data()) != OQS_SUCCESS) {
    OPENSSL_cleanse(secret.data(), secret.size());
    throw std::runtime_error("ML-KEM-768 encapsulation failed");
  }
  state.transcript = pk_nd;
  state.transcript.insert(state.transcript.end(), state.kem_ciphertext.begin(),
                          state.kem_ciphertext.end());
  try {
    deriveHandshakeKeys(state, secret);
  } catch (...) {
    OPENSSL_cleanse(secret.data(), secret.size());
    throw;
  }
  out_wire = state.kem_ciphertext;
  return state;
}

// New device (responder): decapsulate with the private key held in its session.
inline HandshakeState ndHandshakeProcess(
    const std::vector<uint8_t>& kem_ciphertext,
    const std::vector<uint8_t>& pk_nd,
    const std::array<uint8_t, kMlKem768HandshakeSkBytes>& sk_nd) {
  OQS_KEM* raw_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!raw_kem) throw std::runtime_error("ML-KEM-768 unavailable");
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem(raw_kem, &OQS_KEM_free);
  if (pk_nd.size() != kem->length_public_key ||
      kem_ciphertext.size() != kem->length_ciphertext ||
      kem->length_secret_key != sk_nd.size())
    throw std::runtime_error("Invalid ML-KEM-768 handshake input length");

  HandshakeState state;
  std::vector<uint8_t> secret(kem->length_shared_secret);
  if (OQS_KEM_decaps(kem.get(), secret.data(), kem_ciphertext.data(),
                     sk_nd.data()) != OQS_SUCCESS) {
    OPENSSL_cleanse(secret.data(), secret.size());
    throw std::runtime_error("ML-KEM-768 decapsulation failed");
  }
  state.kem_ciphertext = kem_ciphertext;
  state.transcript = pk_nd;
  state.transcript.insert(state.transcript.end(), kem_ciphertext.begin(),
                          kem_ciphertext.end());
  try {
    deriveHandshakeKeys(state, secret);
  } catch (...) {
    OPENSSL_cleanse(secret.data(), secret.size());
    throw;
  }
  return state;
}

}  // namespace internal
}  // namespace auth
