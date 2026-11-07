#include "DeviceSigner.h"

#include "auth/sync_tpm.hpp"

namespace ui {

// DeviceSigner intentionally returns only a software ECDSA P-256 signer.
// TPM 2.0 and Android Keystore code remains in the project (include/auth/tpm2.hpp,
// ui/AndroidKeystoreTpm.h/.cpp) but is never instantiated or called at runtime.
// The working app never prompts for a PIN or touches /dev/tpmrm0 or the
// Android Keystore.
std::unique_ptr<auth::sync::TpmInterface> makeDeviceSigner(QString& error) {
    error.clear();
    return std::make_unique<auth::sync::SoftwareTpm>();
}

}  // namespace ui
