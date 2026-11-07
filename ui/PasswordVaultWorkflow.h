#pragma once

#include "PasswordVaultFileStore.h"
#include "auth/WebsiteCredentialAuth.hpp"

#include <QString>

#include <cstdint>
#include <string>
#include <vector>

class PasswordVaultWorkflow {
public:
    PasswordVaultWorkflow(PasswordVaultStorage &storage,
                          auth::WebsiteCredentialAuthStore &protocol_store);

    std::vector<auth::VaultEntry> unlockAndMigrate(
        const std::vector<uint8_t> &key);
    std::vector<auth::VaultEntry> mergeImportedEntries(
        const std::vector<uint8_t> &key,
        const std::vector<auth::VaultEntry> &imported);
    void saveNewCredential(const std::vector<uint8_t> &key,
                           const QString &website,
                           const std::string &username,
                           const std::vector<uint8_t> &password);
    bool authenticate(const auth::VaultEntry &entry);

    // Trusted-device list T (Protocol 4 VaultSync) -- lives inside encrypted vault payload
    using TrustedDeviceKey = auth::TrustedDeviceKey;

    // List all trusted device keys
    std::vector<TrustedDeviceKey> listTrustedDevices(
        const std::vector<uint8_t> &key) const;

    // Add a device key to T (idempotent: no duplicate if already present).
    // Persists via atomic vault-file store.
    void addTrustedDevice(const std::vector<uint8_t> &key,
                          const TrustedDeviceKey &device_key);

    // Check if a device key is in T
    bool isDeviceTrusted(const std::vector<uint8_t> &key,
                         const TrustedDeviceKey &device_key) const;

    // Remove a device key from T (revoke). Returns true if key was present.
    // Persists via atomic vault-file store.
    bool revokeTrustedDevice(const std::vector<uint8_t> &key,
                             const TrustedDeviceKey &device_key);

private:
    std::vector<auth::RegistrationPayload> prepareRecords(
        std::vector<auth::VaultEntry> &entries,
        bool assignMissingSalts) const;

    // Helper: load and decrypt vault payload (entries + trust list)
    auth::VaultPayload loadPayload(const std::vector<uint8_t> &key) const;

    // Helper: encrypt and save vault payload (entries + trust list)
    void savePayload(const std::vector<uint8_t> &key,
                     const auth::VaultPayload &payload);

    PasswordVaultStorage &storage_;
    auth::WebsiteCredentialAuthStore &protocol_store_;
};
