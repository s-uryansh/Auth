// Platform selection of the Protocol 4 device signer.
// The working app uses only a software ECDSA P-256 signer. TPM 2.0 and
// Android Keystore code remains in the project but is never instantiated
// or called at runtime. makeDeviceSigner never returns nullptr and never
// attempts to access /dev/tpmrm0 or the Android Keystore.
#pragma once

#include "auth/sync_tpm.hpp"

#include <QString>

#include <memory>

namespace ui {

std::unique_ptr<auth::sync::TpmInterface> makeDeviceSigner(QString& error);

}  // namespace ui
