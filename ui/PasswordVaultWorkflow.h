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
    void saveNewCredential(const std::vector<uint8_t> &key,
                           const QString &website,
                           const std::string &username,
                           const std::vector<uint8_t> &password);
    bool authenticate(const auth::VaultEntry &entry);

private:
    std::vector<auth::RegistrationPayload> prepareRecords(
        std::vector<auth::VaultEntry> &entries,
        bool assignMissingSalts) const;

    PasswordVaultStorage &storage_;
    auth::WebsiteCredentialAuthStore &protocol_store_;
};
