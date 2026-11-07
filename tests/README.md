# Tests

Run the configured desktop suites from the repository root with:

```bash
make test
```

The GTest suite in `test_auth.cpp` covers registration, authentication, protocol failure inputs, and vault compatibility. `test_sensitive_data.cpp` covers Qt UTF-8 conversion and sensitive-buffer clearing. `test_vault_storage.cpp` exercises Argon2 key derivation, vault serialization/encryption, tamper rejection, and password-vault file persistence and validation. `test_qrsync.cpp` covers QR framing, five-minute expiry, replay/session gates, KEM transfer helpers, vault tamper rejection, and merge behavior. `QtUiFlowTests` covers scanner navigation, logical-size preview rendering, asynchronous QR decoding, Protocol 4 QR generation/decode round-trip, five-minute QR-session expiry, and removal of the requested Auth controls.

Most interactive Auth and Password Manager flows and Android packaging are not exercised by CTest. `QtUiFlowTests` does not emulate Android's runtime permission dialog or camera hardware; camera access and QR decoding still require device-level validation. The Qt application is built as part of the desktop build; it is not registered as a CTest because its normal event loop does not exit on its own. `make test` checks desktop prerequisites and the CTest runner before building and running the suites.
