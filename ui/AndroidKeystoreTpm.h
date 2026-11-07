// Hardware-backed device signer for Android: a non-exportable EC P-256 key
// inside the Android KeyStore ("AndroidKeyStore" provider), which on
// supported devices is held by the StrongBox/TEE secure element — the
// Protocol 4 equivalent of a desktop TPM (TMPS_Auth.pdf Section IV-C).
// Signing requires a recent user authentication (device PIN, credential, or
// biometric) enforced by the keystore itself.
#pragma once

#include "auth/sync_tpm.hpp"

#include <QString>

#include <memory>

// Returns nullptr with an explanation when the hardware keystore is not
// available (e.g. no secure lock screen or unbacked provider).
std::unique_ptr<auth::sync::TpmInterface> createAndroidKeystoreSigner(
    QString& error);
