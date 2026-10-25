#include "PasswordVaultWorkflow.h"

#include "SensitiveData.h"

#include <stdexcept>
#include <algorithm>
#include <unordered_set>
#include <utility>

namespace {

class VaultEntriesWiper {
public:
    explicit VaultEntriesWiper(std::vector<auth::VaultEntry> &entries)
        : entries_(entries) {}
    ~VaultEntriesWiper() {
        if (active_) ui::wipeVaultEntries(entries_);
    }

    void release() { active_ = false; }

    VaultEntriesWiper(const VaultEntriesWiper &) = delete;
    VaultEntriesWiper &operator=(const VaultEntriesWiper &) = delete;

private:
    std::vector<auth::VaultEntry> &entries_;
    bool active_ = true;
};

void appendWebsiteIfMissing(PasswordVaultFile &vault,
                            const std::string &website) {
    const QString value = QString::fromStdString(website);
    if (!vault.websites.contains(value)) vault.websites.push_back(value);
}

}  // namespace

PasswordVaultWorkflow::PasswordVaultWorkflow(
    PasswordVaultStorage &storage,
    auth::WebsiteCredentialAuthStore &protocol_store)
    : storage_(storage), protocol_store_(protocol_store) {}

std::vector<auth::RegistrationPayload> PasswordVaultWorkflow::prepareRecords(
    std::vector<auth::VaultEntry> &entries,
    bool assignMissingSalts) const {
    std::vector<auth::RegistrationPayload> records;
    records.reserve(entries.size());
    std::unordered_set<std::string> identities;
    identities.reserve(entries.size());

    for (auth::VaultEntry &entry : entries) {
        if (entry.website.empty() || entry.username.empty() ||
            entry.password.empty()) {
            throw std::runtime_error("Vault credential entry is incomplete");
        }
        if (entry.salt.empty() && assignMissingSalts) {
            entry.salt = auth::GenerateSalt();
        }
        if (entry.salt.size() != auth::kSaltSize) {
            throw std::runtime_error("Vault credential protocol salt is invalid");
        }

        const std::string identity = auth::WebsiteCredentialAuthStore::identity(
            entry.website, entry.username);
        if (!identities.insert(identity).second) {
            throw std::runtime_error("Duplicate website and username in vault");
        }

        std::vector<uint8_t> password_copy = entry.password;
        try {
            records.push_back(protocol_store_.prepareRegistration(
                entry.website, entry.username, password_copy, entry.salt));
        } catch (...) {
            ui::wipeBytes(password_copy);
            throw;
        }
        ui::wipeBytes(password_copy);
    }
    return records;
}

std::vector<auth::VaultEntry> PasswordVaultWorkflow::unlockAndMigrate(
    const std::vector<uint8_t> &key) {
    const PasswordVaultFile original = storage_.load();
    std::vector<auth::VaultEntry> entries = auth::DecryptVault(
        key, original.ciphertext, storage_.authenticatedData(original));
    VaultEntriesWiper wipe_entries(entries);

    const bool migrate = original.format_version == 1;
    std::vector<auth::RegistrationPayload> records =
        prepareRecords(entries, migrate);
    auth::WebsiteCredentialAuthStore staged_protocol_store;
    staged_protocol_store.commitRegistrations(records);

    if (migrate) {
        PasswordVaultFile updated = original;
        updated.format_version = 2;
        for (const auth::VaultEntry &entry : entries) {
            appendWebsiteIfMissing(updated, entry.website);
        }
        updated.ciphertext = auth::EncryptVault(
            key, entries, storage_.authenticatedData(updated));
        storage_.save(updated);
    }

    protocol_store_ = std::move(staged_protocol_store);
    wipe_entries.release();
    return entries;
}

std::vector<auth::VaultEntry> PasswordVaultWorkflow::mergeImportedEntries(
    const std::vector<uint8_t> &key,
    const std::vector<auth::VaultEntry> &imported) {
    const PasswordVaultFile original = storage_.load();
    std::vector<auth::VaultEntry> merged = auth::DecryptVault(
        key, original.ciphertext, storage_.authenticatedData(original));
    VaultEntriesWiper wipe_entries(merged);

    for (const auth::VaultEntry &remote : imported) {
        const std::string identity = auth::WebsiteCredentialAuthStore::identity(
            remote.website, remote.username);
        auto existing = std::find_if(merged.begin(), merged.end(),
            [&identity](const auth::VaultEntry &entry) {
                return auth::WebsiteCredentialAuthStore::identity(
                    entry.website, entry.username) == identity;
            });
        if (existing == merged.end()) {
            merged.push_back(remote);
        } else if (remote.lastModified > existing->lastModified) {
            ui::wipeVaultEntry(*existing);
            *existing = remote;
        }
    }

    std::vector<auth::RegistrationPayload> records =
        prepareRecords(merged, original.format_version == 1);
    auth::WebsiteCredentialAuthStore staged_protocol_store;
    staged_protocol_store.commitRegistrations(records);

    PasswordVaultFile updated = original;
    updated.format_version = 2;
    for (const auth::VaultEntry &entry : merged)
        appendWebsiteIfMissing(updated, entry.website);
    updated.ciphertext = auth::EncryptVault(
        key, merged, storage_.authenticatedData(updated));
    storage_.save(updated);

    protocol_store_ = std::move(staged_protocol_store);
    wipe_entries.release();
    return merged;
}

void PasswordVaultWorkflow::saveNewCredential(
    const std::vector<uint8_t> &key,
    const QString &website,
    const std::string &username,
    const std::vector<uint8_t> &password) {
    if (website.isEmpty() || username.empty() || password.empty()) {
        throw std::runtime_error("Website, username, and password are required");
    }

    const PasswordVaultFile original = storage_.load();
    std::vector<auth::VaultEntry> entries = auth::DecryptVault(
        key, original.ciphertext, storage_.authenticatedData(original));
    VaultEntriesWiper wipe_entries(entries);

    const std::string website_bytes = website.toStdString();
    const std::string new_identity = auth::WebsiteCredentialAuthStore::identity(
        website_bytes, username);
    for (const auth::VaultEntry &entry : entries) {
        if (auth::WebsiteCredentialAuthStore::identity(entry.website,
                                                       entry.username) ==
            new_identity) {
            throw std::runtime_error(
                "A credential for this website and username already exists");
        }
    }

    auth::VaultEntry new_entry;
    new_entry.website = website_bytes;
    new_entry.username = username;
    new_entry.password = password;
    new_entry.salt = auth::GenerateSalt();
    entries.push_back(std::move(new_entry));

    std::vector<auth::RegistrationPayload> records =
        prepareRecords(entries, original.format_version == 1);
    auth::WebsiteCredentialAuthStore staged_protocol_store;
    staged_protocol_store.commitRegistrations(records);

    PasswordVaultFile updated = original;
    updated.format_version = 2;
    appendWebsiteIfMissing(updated, website_bytes);
    for (const auth::VaultEntry &entry : entries) {
        appendWebsiteIfMissing(updated, entry.website);
    }
    updated.ciphertext = auth::EncryptVault(
        key, entries, storage_.authenticatedData(updated));
    storage_.save(updated);

    protocol_store_ = std::move(staged_protocol_store);
}

bool PasswordVaultWorkflow::authenticate(const auth::VaultEntry &entry) {
    std::vector<uint8_t> password_copy = entry.password;
    try {
        const bool authenticated = protocol_store_.authenticate(
            entry.website, entry.username, password_copy, entry.salt);
        ui::wipeBytes(password_copy);
        return authenticated;
    } catch (...) {
        ui::wipeBytes(password_copy);
        return false;
    }
}
