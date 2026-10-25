# Tests

Run the configured desktop suites from the repository root with:

```bash
make test
```

The GTest suite in `test_auth.cpp` covers registration, authentication, protocol failure inputs, and vault compatibility. `test_sensitive_data.cpp` covers Qt UTF-8 conversion and sensitive-buffer clearing. `test_vault_storage.cpp` exercises Argon2 key derivation, vault serialization/encryption, tamper rejection, and password-vault file persistence and validation. `test_qrsync.cpp` covers QR framing, five-minute expiry, replay/session gates, KEM transfer helpers, vault tamper rejection, and merge behavior.

Interactive Auth, Password Manager, and camera-scanner widgets and Android packaging flows are not exercised by CTest. QR camera decoding requires device-level validation. The Qt application is built as part of the desktop build; it is not registered as a CTest because its normal event loop does not exit on its own. `make test` checks desktop prerequisites and the CTest runner before building and running the suites.
