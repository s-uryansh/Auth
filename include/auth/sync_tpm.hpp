// TPM Interface and Software Mock for Protocol 4
// Phase A (pre-flight) and Phase F (approval/signing)

#pragma once

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "auth/ecdsa_wire.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace auth {
namespace sync {

class TpmInterface {
public:
  virtual ~TpmInterface() = default;
  // Describes the signing implementation; this is not a hardware attestation.
  virtual const char* backendName() const noexcept { return "custom signing backend"; }
  // True when the signing key is held in hardware (TPM 2.0, Secure Element,
  // Android Keystore). False for software-only fallbacks.
  virtual bool isHardwareBacked() const noexcept { return false; }
  virtual bool hasTPM() const = 0;
  // Optional user authorization value (PIN) guarding the device signing
  // key, per Protocol 4 Section IV-C. Backends without support report
  // false and keep pairing disabled for the caller to surface.
  virtual bool setAuthorization(const std::vector<uint8_t>&) { return false; }
  virtual void createKey() = 0;
  virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& message) = 0;
  virtual bool verify(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& pubkey) = 0;
  virtual std::vector<uint8_t> getPubkey() const = 0;
  virtual void wipe() = 0;
};

// Software-only ECDSA P-256 signer used as fallback when no hardware TPM or
// secure element is available. Produces the same wire format as the hardware
// backends: raw 64-byte r||s signatures and 65-byte uncompressed SEC1 points
// (0x04 || x || y), interoperable through ecdsa_wire.hpp.
//
// This is an in-memory software signer used as fallback. It does not provide
// TPM properties (non-exportability, hardware-bound PIN gating).
class SoftwareTpm : public TpmInterface {
public:
  SoftwareTpm() = default;
  ~SoftwareTpm() override { wipe(); }

  SoftwareTpm(const SoftwareTpm&) = delete;
  SoftwareTpm& operator=(const SoftwareTpm&) = delete;
  SoftwareTpm(SoftwareTpm&&) = delete;
  SoftwareTpm& operator=(SoftwareTpm&&) = delete;

  const char* backendName() const noexcept override {
    return "software-only ECDSA P-256 signer";
  }
  bool hasTPM() const override { return false; }
  bool isHardwareBacked() const noexcept override { return false; }

  void createKey() override {
    wipe();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed");
    char group[] = "P-256";
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", group, 0),
        OSSL_PARAM_construct_end()};
    EVP_PKEY* generated = nullptr;
    if (EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_params(ctx, const_cast<OSSL_PARAM*>(params)) != 1 ||
        EVP_PKEY_keygen(ctx, &generated) != 1) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);
    pkey_.reset(generated);
    if (!pkey_) throw std::runtime_error("null P-256 key");
    exportPubkey();
  }

  std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
    if (!pkey_) throw std::runtime_error("Signing key not created");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    bool ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr,
                                 pkey_.get()) == 1 &&
              EVP_DigestSignUpdate(ctx, message.data(), message.size()) == 1;
    size_t der_len = 0;
    if (ok) ok = EVP_DigestSignFinal(ctx, nullptr, &der_len) == 1;
    std::vector<uint8_t> der(der_len);
    if (ok) ok = EVP_DigestSignFinal(ctx, der.data(), &der_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw std::runtime_error("ECDSA sign failed");
    der.resize(der_len);
    return auth::sync::ecdsaDerSignatureToRaw(der);
  }

  bool verify(const std::vector<uint8_t>& message,
              const std::vector<uint8_t>& signature,
              const std::vector<uint8_t>& pubkey) override {
    return auth::sync::ecdsaVerifySha256(message, signature, pubkey);
  }

  std::vector<uint8_t> getPubkey() const override { return pubkey_; }

  void wipe() override {
    if (!pubkey_.empty()) OPENSSL_cleanse(pubkey_.data(), pubkey_.size());
    pubkey_.clear();
    pkey_.reset();
  }

private:
  // Export the public key as a 65-byte uncompressed SEC1 point.
  void exportPubkey() {
    if (!pkey_) return;
    unsigned char* der = nullptr;
    const int der_len = i2d_PUBKEY(pkey_.get(), &der);
    if (der_len <= 0 || !der) {
      if (der) OPENSSL_free(der);
      return;
    }
    const std::vector<uint8_t> der_vec(der, der + der_len);
    OPENSSL_free(der);
    pubkey_ = auth::sync::ecdsaDerPublicKeyToPoint(der_vec);
  }

  struct PKeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
  };
  using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDeleter>;

  PKeyPtr pkey_;
  std::vector<uint8_t> pubkey_;
};

class NullTpm : public TpmInterface {
public:
  const char* backendName() const noexcept override { return "no signing backend"; }
  bool hasTPM() const override { return false; }
  bool isHardwareBacked() const noexcept override { return false; }
  void createKey() override {}
  std::vector<uint8_t> sign(const std::vector<uint8_t>&) override { return {}; }
  bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
              const std::vector<uint8_t>&) override { return false; }
  std::vector<uint8_t> getPubkey() const override { return {}; }
  void wipe() override {}
};

}  // namespace sync
}  // namespace auth
