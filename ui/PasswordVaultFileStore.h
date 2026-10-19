#pragma once

#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

#include "auth/vault.hpp"

struct PasswordVaultFile {
    std::vector<uint8_t> salt;
    auth::Argon2Params params{};
    std::vector<uint8_t> ciphertext;
    QStringList websites;
};

class PasswordVaultFileStore {
public:
    explicit PasswordVaultFileStore(QString filePath);

    bool exists() const;
    PasswordVaultFile load() const;
    void save(const PasswordVaultFile &vault) const;

private:
    QString file_path_;
};
