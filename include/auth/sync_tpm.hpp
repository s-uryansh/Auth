// TPM Interface and Software Mock for Protocol 4
// Phase A (pre-flight) and Phase F (approval/signing)

#pragma once

#include <oqs/sig.h>
#include <openssl/crypto.h>

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

  // This is an in-memory test signer.  It does not provide TPM properties.
  const char* backendName() const noexcept override { return "software-only test signer"; }
  bool hasTPM() const override { return false; }

  void createKey() override {
    wipe();
    OqsSigPtr candidate(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65));
    if (!candidate) throw std::runtime_error("OQS_SIG_new failed");

    std::vector<uint8_t> candidate_pubkey(candidate->length_public_key);
    std::vector<uint8_t> candidate_secret(candidate->length_secret_key);
    try {
      if (OQS_SIG_keypair(candidate.get(), candidate_pubkey.data(),
                          candidate_secret.data()) != OQS_SUCCESS) {
        throw std::runtime_error("OQS_SIG_keypair failed");
      }
    } catch (...) {
      cleanse(candidate_pubkey);
      cleanse(candidate_secret);
      throw;
    }

    sig_ = candidate.release();
    pubkey_ = std::move(candidate_pubkey);
    sk_ = std::move(candidate_secret);
  }

  std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
    if (!sig_ || sk_.empty()) throw std::runtime_error("Signing key not created");
    size_t sig_len = sig_->length_signature;
    std::vector<uint8_t> signature(sig_len);
    size_t actual_len = sig_len;
    if (OQS_SIG_sign(sig_, signature.data(), &actual_len,
                     messageData(message), message.size(), sk_.data()) != OQS_SUCCESS) {
      cleanse(signature);
      throw std::runtime_error("OQS_SIG_sign failed");
    }
    if (actual_len == 0 || actual_len > signature.size()) {
      cleanse(signature);
      throw std::runtime_error("OQS_SIG_sign returned invalid signature length");
    }
    signature.resize(actual_len);
    return signature;
  }

  bool verify(const std::vector<uint8_t>& message,
              const std::vector<uint8_t>& signature,
              const std::vector<uint8_t>& pubkey) override {
    OqsSigPtr verifier(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65));
    if (!verifier || signature.empty() ||
        pubkey.size() != verifier->length_public_key ||
        signature.size() > verifier->length_signature) {
      return false;
    }
    return OQS_SIG_verify(verifier.get(), messageData(message), message.size(),
                          signature.data(), signature.size(),
                          pubkey.data()) == OQS_SUCCESS;
  }

  std::vector<uint8_t> getPubkey() const override {
    return pubkey_;
  }

  void wipe() override {
    cleanse(sk_);
    cleanse(pubkey_);
    if (sig_) OQS_SIG_free(sig_);
    sig_ = nullptr;
    pubkey_.clear();
    sk_.clear();
  }

private:
  struct OqsSigDeleter {
    void operator()(OQS_SIG* signature_scheme) const noexcept {
      if (signature_scheme) OQS_SIG_free(signature_scheme);
    }
  };

  using OqsSigPtr = std::unique_ptr<OQS_SIG, OqsSigDeleter>;

  static const uint8_t* messageData(const std::vector<uint8_t>& message) noexcept {
    static constexpr uint8_t kEmptyMessage = 0;
    return message.empty() ? &kEmptyMessage : message.data();
  }

  static void cleanse(std::vector<uint8_t>& bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
  }

  OQS_SIG* sig_ = nullptr;
  std::vector<uint8_t> pubkey_;
  std::vector<uint8_t> sk_;
};

class NullTpm : public TpmInterface {
public:
  const char* backendName() const noexcept override { return "no signing backend"; }
  bool hasTPM() const override { return false; }
  void createKey() override {}
  std::vector<uint8_t> sign(const std::vector<uint8_t>&) override { return {}; }
  bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
              const std::vector<uint8_t>&) override { return false; }
  std::vector<uint8_t> getPubkey() const override { return {}; }
  void wipe() override {}
};

}  // namespace sync
}  // namespace auth
