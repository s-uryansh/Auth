#pragma once

#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

#include "auth/vault.hpp"

struct PasswordVaultFile {
    quint16 format_version = 2;
    std::vector<uint8_t> salt;
    auth::Argon2Params params{};
    std::vector<uint8_t> ciphertext;
    QStringList websites;
};

class PasswordVaultStorage {
public:
    virtual ~PasswordVaultStorage() = default;
    virtual PasswordVaultFile load() const = 0;
    virtual void save(const PasswordVaultFile &vault) const = 0;
    virtual std::vector<uint8_t> authenticatedData(
        const PasswordVaultFile &vault) const = 0;
};

class PasswordVaultFileStore final : public PasswordVaultStorage {
public:
    explicit PasswordVaultFileStore(QString filePath);

    bool exists() const;
    // Deletes the vault file. Used only for a corrupted vault that can never be
    // decrypted again; the caller is responsible for confirming with the user.
    bool remove();
    PasswordVaultFile load() const override;
    void save(const PasswordVaultFile &vault) const override;
    std::vector<uint8_t> authenticatedData(
        const PasswordVaultFile &vault) const override;

private:
    QString file_path_;
};
