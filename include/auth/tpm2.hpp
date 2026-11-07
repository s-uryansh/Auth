// TPM 2.0 signing support via tpm2-tss ESAPI.
// Compiled only when HAVE_TPM2_TSS is defined (requires libtss2-esys-dev headers).
// When TPM is unavailable, QRSyncTab falls back to SoftwareTpm.
//
// Protocol 4 (TMPS_Auth.pdf Section IV-C): each device holds a TPM-resident
// signing key (skdev, pkdev). skdev never leaves the TPM; signing requires
// user authorization (PIN/biometric). The public key pkdev serves as the
// device identity and is exchanged during QR sync.

#pragma once

#include "auth/sync_tpm.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#ifdef HAVE_TPM2_TSS
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#endif

namespace auth {
namespace sync {

#ifdef HAVE_TPM2_TSS

class Tpm2Tpm : public TpmInterface {
public:
  Tpm2Tpm();
  ~Tpm2Tpm() override;

  Tpm2Tpm(const Tpm2Tpm&) = delete;
  Tpm2Tpm& operator=(const Tpm2Tpm&) = delete;
  Tpm2Tpm(Tpm2Tpm&&) = delete;
  Tpm2Tpm& operator=(Tpm2Tpm&&) = delete;

  bool hasTPM() const noexcept override { return esys_ctx_ != nullptr; }
  void createKey() override;
  std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override;
  bool verify(const std::vector<uint8_t>& message,
              const std::vector<uint8_t>& signature,
              const std::vector<uint8_t>& public_key) override;
  std::vector<uint8_t> getPubkey() const override;
  void wipe() override;

  const char* backendName() const noexcept override {
    return "TPM 2.0 (tpm2-tss ESAPI)";
  }

private:
  ESYS_CONTEXT* esys_ctx_ = nullptr;
  ESYS_TR key_handle_ = ESYS_TR_NONE;
  std::vector<uint8_t> pubkey_;

  void initEsysContext();
  void createSigningKey();
  void exportPublicKey();
  std::vector<uint8_t> sha256Digest(const std::vector<uint8_t>& data) const;
};

inline Tpm2Tpm::Tpm2Tpm() { initEsysContext(); }

inline Tpm2Tpm::~Tpm2Tpm() {
  wipe();
  if (esys_ctx_) Esys_Finalize(&esys_ctx_);
}

inline void Tpm2Tpm::initEsysContext() {
  TSS2_TCTI_CONTEXT* tcti = nullptr;
  TSS2_RC rc = Tss2_TctiLdr_Initialize("device:/dev/tpm0", &tcti);
  if (rc != TSS2_RC_SUCCESS)
    rc = Tss2_TctiLdr_Initialize("mssim:127.0.0.1:2321", &tcti);
  if (rc != TSS2_RC_SUCCESS || !tcti) { esys_ctx_ = nullptr; return; }
  if (Esys_Initialize(&esys_ctx_, tcti, nullptr) != TSS2_RC_SUCCESS) {
    esys_ctx_ = nullptr;
  }
}

inline void Tpm2Tpm::createKey() {
  if (!esys_ctx_) throw std::runtime_error("TPM context not initialized");

  TPM2B_PUBLIC inPublic = {};
  inPublic.publicArea.type = TPM2_ALG_ECC;
  inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
  inPublic.publicArea.objectAttributes =
      TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT |
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN;
  inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
  inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
  inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
      TPM2_ALG_SHA256;
  inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

  TPM2B_SENSITIVE_CREATE inSensitive = {};
  inSensitive.sensitive.userAuth.size = 0;
  inSensitive.sensitive.data.size = 0;

  TPM2B_PUBLIC* out_public = nullptr;
  TSS2_RC rc = Esys_CreatePrimary(esys_ctx_,
                                  ESYS_TR_RH_OWNER,
                                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &inSensitive, &inPublic,
                                  nullptr, nullptr,
                                  &key_handle_, &out_public,
                                  nullptr, nullptr, nullptr);
  if (rc != TSS2_RC_SUCCESS) throw std::runtime_error("Esys_CreatePrimary failed");

  exportPublicKey();
}

inline std::vector<uint8_t> Tpm2Tpm::sign(
    const std::vector<uint8_t>& message) {
  if (!esys_ctx_) throw std::runtime_error("TPM context not initialized");
  if (key_handle_ == ESYS_TR_NONE)
    throw std::runtime_error("TPM signing key not created");

  auto digest = sha256Digest(message);
  TPM2B_DIGEST tpm_digest = {};
  tpm_digest.size = static_cast<uint16_t>(digest.size());
  std::memcpy(tpm_digest.buffer, digest.data(), digest.size());

  TPMT_SIG_SCHEME scheme = {};
  scheme.scheme = TPM2_ALG_ECDSA;
  scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

  TPMT_SIGNATURE* signature = nullptr;
  TSS2_RC rc = Esys_Sign(esys_ctx_,
                         key_handle_,
                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &tpm_digest,
                         &scheme,
                         nullptr,
                         &signature);
  if (rc != TSS2_RC_SUCCESS || !signature)
    throw std::runtime_error("Esys_Sign failed");

  std::vector<uint8_t> result;
  if (signature->signature.ecdsa.signatureR.size > 0 &&
      signature->signature.ecdsa.signatureS.size > 0) {
    result.reserve(signature->signature.ecdsa.signatureR.size +
                   signature->signature.ecdsa.signatureS.size);
    result.insert(result.end(),
                  signature->signature.ecdsa.signatureR.buffer,
                  signature->signature.ecdsa.signatureR.buffer +
                      signature->signature.ecdsa.signatureR.size);
    result.insert(result.end(),
                  signature->signature.ecdsa.signatureS.buffer,
                  signature->signature.ecdsa.signatureS.buffer +
                      signature->signature.ecdsa.signatureS.size);
  }
  return result;
}

inline bool Tpm2Tpm::verify(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {
  // Verify outside TPM using OpenSSL with exported public key
  // Build EC public key from uncompressed point: 0x04 || x(32) || y(32)
  if (public_key.size() != 65 || public_key[0] != 0x04) return false;

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, nullptr,
                                               public_key.data() + 1, 64);
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) { EVP_PKEY_free(pkey); return false; }

  bool ok = false;
  if (EVP_DigestVerifyInit_ex(ctx, nullptr, "SHA256", nullptr, nullptr, pkey, nullptr) == 1 &&
      EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) == 1 &&
      EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1) {
    ok = true;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

inline std::vector<uint8_t> Tpm2Tpm::getPubkey() const { return pubkey_; }

inline void Tpm2Tpm::wipe() {
  if (key_handle_ != ESYS_TR_NONE && esys_ctx_) {
    Esys_FlushContext(esys_ctx_, key_handle_);
    key_handle_ = ESYS_TR_NONE;
  }
  pubkey_.clear();
  pubkey_.shrink_to_fit();
}

inline void Tpm2Tpm::exportPublicKey() {
  if (!esys_ctx_ || key_handle_ == ESYS_TR_NONE) return;
  TPM2B_PUBLIC* out_public = nullptr;
  if (Esys_ReadPublic(esys_ctx_,
                      key_handle_,
                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                      &out_public, nullptr, nullptr) != TSS2_RC_SUCCESS) {
    return;
  }
  if (!out_public) return;

  // Extract uncompressed ECC point: 0x04 || x(32) || y(32)
  pubkey_.clear();
  pubkey_.push_back(0x04);
  // publicArea.unique.ecc is TPMS_ECC_POINT with x and y (TPM2B_ECC_PARAMETER)
  const auto& x = out_public->publicArea.unique.ecc.x;
  const auto& y = out_public->publicArea.unique.ecc.y;
  pubkey_.insert(pubkey_.end(), x.buffer, x.buffer + x.size);
  pubkey_.insert(pubkey_.end(), y.buffer, y.buffer + y.size);
}

inline std::vector<uint8_t> Tpm2Tpm::sha256Digest(
    const std::vector<uint8_t>& data) const {
  std::vector<uint8_t> digest(32);
  unsigned int len = 0;
  if (EVP_Digest(data.data(), data.size(), digest.data(), &len,
                 EVP_sha256(), nullptr) != 1 || len != 32) {
    throw std::runtime_error("SHA-256 failed");
  }
  return digest;
}

#else  // HAVE_TPM2_TSS

class Tpm2Tpm : public TpmInterface {
public:
  Tpm2Tpm() = default;
  ~Tpm2Tpm() override = default;

  bool hasTPM() const noexcept override { return false; }
  void createKey() override { throw std::runtime_error("TPM2 not available"); }
  std::vector<uint8_t> sign(const std::vector<uint8_t>&) override {
    throw std::runtime_error("TPM2 not available");
  }
  bool verify(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
              const std::vector<uint8_t>&) override {
    throw std::runtime_error("TPM2 not available");
  }
  std::vector<uint8_t> getPubkey() const override {
    throw std::runtime_error("TPM2 not available");
  }
  void wipe() override {}

  const char* backendName() const noexcept override {
    return "TPM2 not available (stub)";
  }
};

#endif  // HAVE_TPM2_TSS

}  // namespace sync
}  // namespace auth
