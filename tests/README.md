# Tests

Run the configured desktop suites from the repository root with:

```bash
make test
```

`test_auth.cpp` (AuthUnitTests) covers registration, authentication, protocol failure inputs, and vault compatibility. `test_sensitive_data.cpp` (SensitiveDataTests) covers Qt UTF-8 conversion and sensitive-buffer clearing. `test_vault_storage.cpp` (VaultStorageTests) exercises Argon2 key derivation, vault serialization/encryption, tamper rejection, and password-vault file persistence and validation. `test_password_manager_workflow.cpp` (PasswordManagerWorkflowTests) covers the unlock/migrate/save workflow. `test_qrsync.cpp` (QRSyncTests) covers QR framing, five-minute expiry, replay/session gates, KEM transfer helpers, vault tamper rejection, and merge behavior. `test_qrsync_protocol_unit.cpp` (QRSyncProtocolUnitTests) covers the Protocol 4 approval digests, signature acceptance, and the single-use consumption of a verified session. `test_sync_tpm.cpp` plus `test_ecdsa_wire.cpp` (SyncTpmTests) cover the software test signer, the cross-platform ECDSA P-256 wire codecs, and the TPM 2.0 backend — the real-hardware cases run only when a TPM is reachable (`/dev/tpmrm0` access via the `tss` group, or `AUTH_TPM_SIMULATOR=1` with a simulator on port 2321) and skip with guidance otherwise. `test_sync_trust_storage.cpp` (SyncTrustStoreTests) covers the encrypted trusted-device list inside the vault payload.

`QtUiFlowTests` runs the real Qt widgets offscreen: scanner navigation, logical-size preview rendering, asynchronous QR decoding, Protocol 4 QR generation/decode round-trip, five-minute QR-session expiry, removal of the requested Auth controls, and the Protocol 4 loopback gate suite in `test_qrsync_integration.cpp` — the old device refuses a KEM frame before verifying σND and releases the vault exactly once after; the new device auto-signs σND and encapsulates after a verified approval with no extra gesture; a failed import never acknowledges; successful syncs record the peer device keys in the vault.

Most interactive Auth and Password Manager flows and Android packaging are not exercised by CTest. `QtUiFlowTests` does not emulate Android's runtime permission dialog, camera hardware, the TPM device file, or the Android Keystore; hardware signing and two-device pairing still require device-level validation. The Qt application is built as part of the desktop build; it is not registered as a CTest because its normal event loop does not exit on its own. `make test` checks desktop prerequisites and the CTest runner before building and running the suites.
