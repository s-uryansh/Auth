// TPM 2.0 signing support via tpm2-tss ESAPI.
// Compiled only when HAVE_TPM2_TSS is defined (requires libtss2-esys-dev
// headers). When no TPM can be reached the signer reports hasTPM() ==
// false and the app keeps QR pairing disabled.
//
// Protocol 4 (TMPS_Auth.pdf Section IV-C): each device holds a TPM-resident
// signing key (skdev, pkdev). skdev never leaves the TPM; signing requires
// the user's authorization value. pkdev serves as the device identity and
// is exchanged during QR sync. The key here is an Endorsement-hierarchy
// primary key: with a fixed template (and PIN) it deterministically derives
// the same identity in every run without the private part ever leaving the
// chip.
#pragma once

#include "auth/ecdsa_wire.hpp"
#include "auth/sync_tpm.hpp"

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <cstdint>
#include <cstdlib>
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
  // The user PIN authorizing use of skdev; set before createKey() and
  // required for every signature. Changing it changes the derived identity.
  bool setAuthorization(const std::vector<uint8_t>& pin) override {
      auth_value_ = pin;
      return true;
  }
  bool isHardwareBacked() const noexcept override { return true; }
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
  std::vector<uint8_t> auth_value_;

  void initEsysContext();
  void exportPublicKey();
  std::vector<uint8_t> sha256Digest(const std::vector<uint8_t>& data) const;
};

inline Tpm2Tpm::Tpm2Tpm() { initEsysContext(); }

inline Tpm2Tpm::~Tpm2Tpm() {
  wipe();
  if (esys_ctx_) Esys_Finalize(&esys_ctx_);
}

inline void Tpm2Tpm::initEsysContext() {
  // The kernel resource manager is preferred (it multiplexes TPM access);
  // then direct device access. The mssim probe is opt-in via the
  // AUTH_TPM_SIMULATOR environment variable because the tss2-tcti loader
  // leaks a partially initialised context when no simulator is listening.
  std::vector<const char*> candidates = {
      "device:/dev/tpmrm0",
      "device:/dev/tpm0",
  };
  if (const char* simulator = std::getenv("AUTH_TPM_SIMULATOR");
      simulator && *simulator) {
    candidates.push_back("mssim:127.0.0.1:2321");
  }
  for (const char* candidate : candidates) {
    TSS2_TCTI_CONTEXT* tcti = nullptr;
    if (Tss2_TctiLdr_Initialize(candidate, &tcti) != TSS2_RC_SUCCESS || !tcti)
      continue;
    if (Esys_Initialize(&esys_ctx_, tcti, nullptr) == TSS2_RC_SUCCESS &&
        esys_ctx_) {
      return;
    }
    esys_ctx_ = nullptr;
    Tss2_TctiLdr_Finalize(&tcti);
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
  const uint16_t auth_size =
      static_cast<uint16_t>(auth_value_.size() > sizeof(inSensitive.sensitive.userAuth.buffer)
                                ? sizeof(inSensitive.sensitive.userAuth.buffer)
                                : auth_value_.size());
  inSensitive.sensitive.userAuth.size = auth_size;
  if (auth_size > 0) {
    std::memcpy(inSensitive.sensitive.userAuth.buffer, auth_value_.data(), auth_size);
  }
  inSensitive.sensitive.data.size = 0;

  // Deterministic device identity that requires no persistent-handle
  // provisioning. Try the Endorsement hierarchy first (stable across TPM
  // clears), then fall back to the Owner hierarchy — some TPMs require
  // authorization on EPS, so the working hierarchy becomes the identity root.
  // Either hierarchy yields a stable key for a given (template, auth_value).
  ESYS_TR hierarchies[] = {ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_OWNER};
  TSS2_RC rc = TSS2_RC_SUCCESS;
  bool created = false;
  for (ESYS_TR hier : hierarchies) {
    rc = Esys_CreatePrimary(esys_ctx_, hier,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &inSensitive, &inPublic,
                            nullptr, nullptr,
                            &key_handle_, nullptr,
                            nullptr, nullptr, nullptr);
    if (rc == TSS2_RC_SUCCESS) {
      created = true;
      break;
    }
  }
  if (!created) {
    throw std::runtime_error("could not create the device key on the TPM "
                             "(check the PIN: the identity depends on it)");
  }

  exportPublicKey();
}

inline std::vector<uint8_t> Tpm2Tpm::sign(
    const std::vector<uint8_t>& message) {
  if (!esys_ctx_) throw std::runtime_error("TPM context not initialized");
  if (key_handle_ == ESYS_TR_NONE)
    throw std::runtime_error("TPM signing key not created");

  if (!auth_value_.empty()) {
    TPM2B_AUTH auth = {};
    auth.size = static_cast<uint16_t>(auth_value_.size());
    std::memcpy(auth.buffer, auth_value_.data(), auth_value_.size());
    if (Esys_TR_SetAuth(esys_ctx_, key_handle_, &auth) != TSS2_RC_SUCCESS)
      throw std::runtime_error("Esys_TR_SetAuth failed");
  }

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
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &tpm_digest,
                         &scheme,
                         nullptr,
                         &signature);
  if (rc != TSS2_RC_SUCCESS || !signature) {
    if (signature) Esys_Free(signature);
    throw std::runtime_error("Esys_Sign failed (wrong PIN or locked key)");
  }

  // Normalise to the fixed 64-byte wire form: r(32) || s(32), zero-padded.
  std::vector<uint8_t> result(64, 0);
  const auto& r = signature->signature.ecdsa.signatureR;
  const auto& s = signature->signature.ecdsa.signatureS;
  if (r.size > 32 || s.size > 32) {
    Esys_Free(signature);
    throw std::runtime_error("TPM returned an oversized ECDSA signature");
  }
  std::memcpy(result.data() + 32 - r.size, r.buffer, r.size);
  std::memcpy(result.data() + 64 - s.size, s.buffer, s.size);
  Esys_Free(signature);
  return result;
}

inline bool Tpm2Tpm::verify(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {
  // Common wire format shared with the Android keystore backend: raw
  // 64-byte r||s signature verified over a 65-byte uncompressed P-256 point.
  return auth::sync::ecdsaVerifySha256(message, signature, public_key);
}

inline std::vector<uint8_t> Tpm2Tpm::getPubkey() const { return pubkey_; }

inline void Tpm2Tpm::wipe() {
  if (key_handle_ != ESYS_TR_NONE && esys_ctx_) {
    Esys_FlushContext(esys_ctx_, key_handle_);
    key_handle_ = ESYS_TR_NONE;
  }
  if (!auth_value_.empty()) {
    OPENSSL_cleanse(auth_value_.data(), auth_value_.size());
    auth_value_.clear();
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

  // Uncompressed SEC1 point 0x04 || x(32) || y(32), zero-padded to the
  // fixed wire width.
  const auto& x = out_public->publicArea.unique.ecc.x;
  const auto& y = out_public->publicArea.unique.ecc.y;
  if (x.size <= 32 && y.size <= 32) {
    pubkey_.assign(65, 0);
    pubkey_[0] = 0x04;
    std::memcpy(pubkey_.data() + 1 + 32 - x.size, x.buffer, x.size);
    std::memcpy(pubkey_.data() + 33 + 32 - y.size, y.buffer, y.size);
  } else {
    pubkey_.clear();
  }
  Esys_Free(out_public);
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
  bool isHardwareBacked() const noexcept override { return false; }
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
