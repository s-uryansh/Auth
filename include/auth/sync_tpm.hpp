// TPM Interface and Software Mock for Protocol 4
// Phase A (pre-flight) and Phase F (approval/signing)

#pragma once

#include <oqs/sig.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <iostream>

#include <array>
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
  virtual bool hasTPM() const = 0;
  virtual void createKey() = 0;
  virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& message) = 0;
  virtual bool verify(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& pubkey) = 0;
  virtual std::vector<uint8_t> getPubkey() const = 0;
  virtual void wipe() = 0;
};

class SoftwareTpm : public TpmInterface {
public:
  SoftwareTpm() = default;
  ~SoftwareTpm() override { wipe(); }

  SoftwareTpm(const SoftwareTpm&) = delete;
  SoftwareTpm& operator=(const SoftwareTpm&) = delete;
  SoftwareTpm(SoftwareTpm&&) = delete;
  SoftwareTpm& operator=(SoftwareTpm&&) = delete;

  const char* backendName() const noexcept override { return "software-only mock"; }
  bool hasTPM() const override { return false; }

  void createKey() override {
    wipe();
    sig_ = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_) throw std::runtime_error("OQS_SIG_new failed");
    try {
      pubkey_.resize(sig_->length_public_key);
      sk_.resize(sig_->length_secret_key);
      if (OQS_SIG_keypair(sig_, pubkey_.data(), sk_.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_SIG_keypair failed");
    } catch (...) {
      wipe();
      throw;
    }
  }

  std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
    if (!sig_ || sk_.empty()) throw std::runtime_error("Signing key not created");
    size_t sig_len = sig_->length_signature;
    std::vector<uint8_t> signature(sig_len);
    size_t actual_len = sig_len;
    if (OQS_SIG_sign(sig_, signature.data(), &actual_len,
                     message.data(), message.size(), sk_.data()) != OQS_SUCCESS)
      throw std::runtime_error("OQS_SIG_sign failed");
    signature.resize(actual_len);
    return signature;
  }

  bool verify(const std::vector<uint8_t>& message,
              const std::vector<uint8_t>& signature,
              const std::vector<uint8_t>& pubkey) override {
    if (!sig_ || signature.empty() || pubkey.size() != sig_->length_public_key)
      return false;
    return OQS_SIG_verify(sig_, message.data(), message.size(),
                          signature.data(), signature.size(),
                          pubkey.data()) == OQS_SUCCESS;
  }

  std::vector<uint8_t> getPubkey() const override {
    return pubkey_;
  }

  void wipe() override {
    if (!sk_.empty()) OPENSSL_cleanse(sk_.data(), sk_.size());
    if (sig_) OQS_SIG_free(sig_);
    sig_ = nullptr;
    pubkey_.clear();
    sk_.clear();
  }

private:
  OQS_SIG* sig_ = nullptr;
  std::vector<uint8_t> pubkey_;
  std::vector<uint8_t> sk_;
};

class NullTpm : public TpmInterface {
public:
  const char* backendName() const noexcept override { return "no signing backend"; }
  bool hasTPM() const override {
    std::cerr << "[Warning] No TPM present; TPM operations will be no-ops." << std::endl;
    return false;
  }
  void createKey() override {
    std::cerr << "[Warning] TPM key creation skipped (no TPM)." << std::endl;
  }
  std::vector<uint8_t> sign(const std::vector<uint8_t>&) override {
    std::cerr << "[Warning] TPM signing skipped (no TPM)." << std::endl;
    return {};
  }
  bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&, const std::vector<uint8_t>&) override {
    std::cerr << "[Warning] TPM verification skipped (no TPM)." << std::endl;
    return false;
  }
  std::vector<uint8_t> getPubkey() const override {
    std::cerr << "[Warning] TPM public key retrieval skipped (no TPM)." << std::endl;
    return {};
  }
  void wipe() override {
    std::cerr << "[Warning] TPM wipe skipped (no TPM)." << std::endl;
  }
};

}  // namespace sync
}  // namespace auth
