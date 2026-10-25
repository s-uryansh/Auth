#include "PasswordVaultFileStore.h"
#include "PasswordVaultWorkflow.h"

#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

class MemoryVaultStorage final : public PasswordVaultStorage {
public:
    mutable PasswordVaultFile file;
    mutable bool reject_save = false;
    mutable int save_count = 0;

    PasswordVaultFile load() const override { return file; }

    void save(const PasswordVaultFile &vault) const override {
        if (reject_save) throw std::runtime_error("Injected vault save failure");
        file = vault;
        ++save_count;
    }

    std::vector<uint8_t> authenticatedData(
        const PasswordVaultFile &vault) const override {
        const PasswordVaultFileStore encoder(QStringLiteral("unused-test-path"));
        return encoder.authenticatedData(vault);
    }
};

std::vector<uint8_t> bytes(const std::string &text) {
    return {text.begin(), text.end()};
}

PasswordVaultFile makeVault(const MemoryVaultStorage &storage,
                            const std::vector<uint8_t> &key,
                            quint16 version,
                            const std::vector<auth::VaultEntry> &entries) {
    PasswordVaultFile vault;
    vault.format_version = version;
    vault.salt.assign(auth::kSaltSize, 0x31);
    vault.params = auth::kDefaultArgon2Params;
    for (const auth::VaultEntry &entry : entries) {
        const QString website = QString::fromStdString(entry.website);
        if (!vault.websites.contains(website)) vault.websites.push_back(website);
    }
    vault.ciphertext = auth::EncryptVault(
        key, entries, storage.authenticatedData(vault));
    return vault;
}

void expectSameFile(const PasswordVaultFile &left,
                    const PasswordVaultFile &right) {
    EXPECT_EQ(left.format_version, right.format_version);
    EXPECT_EQ(left.salt, right.salt);
    EXPECT_EQ(left.params.memory_cost_kb, right.params.memory_cost_kb);
    EXPECT_EQ(left.params.time_cost, right.params.time_cost);
    EXPECT_EQ(left.params.parallelism, right.params.parallelism);
    EXPECT_EQ(left.params.key_length, right.params.key_length);
    EXPECT_EQ(left.ciphertext, right.ciphertext);
    EXPECT_EQ(left.websites, right.websites);
}

TEST(PasswordVaultWorkflowTest, AddPersistsPerSiteSaltAndProtocolRecord) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    const auto password = bytes("UserEnteredCredential1!");

    workflow.saveNewCredential(key, QStringLiteral("https://example.com"),
                               "alice", password);

    const auto entries = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].website, "https://example.com");
    EXPECT_EQ(entries[0].username, "alice");
    EXPECT_EQ(entries[0].password, password);
    ASSERT_EQ(entries[0].salt.size(), auth::kSaltSize);
    EXPECT_NE(entries[0].salt, storage.file.salt);
    auto login_password = password;
    EXPECT_TRUE(protocol_store.authenticate(entries[0].website,
                                            entries[0].username,
                                            login_password, entries[0].salt));
}

TEST(PasswordVaultWorkflowTest, SameUsernameAtDifferentWebsitesCanBeAdded) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    const auto password = bytes("SharedUsernameCredential1!");

    workflow.saveNewCredential(key, QStringLiteral("https://one.example"),
                               "shared-user", password);
    workflow.saveNewCredential(key, QStringLiteral("https://two.example"),
                               "shared-user", password);

    const auto entries = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_NE(auth::WebsiteCredentialAuthStore::identity(entries[0].website,
                                                          entries[0].username),
              auth::WebsiteCredentialAuthStore::identity(entries[1].website,
                                                          entries[1].username));
}

TEST(PasswordVaultWorkflowTest, DuplicateWebsiteUsernameDoesNotOverwrite) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    const auto original_password = bytes("OriginalEntryPassword1!");
    workflow.saveNewCredential(key, QStringLiteral("https://example.com"),
                               "alice", original_password);
    const PasswordVaultFile original_file = storage.file;

    EXPECT_THROW(workflow.saveNewCredential(
                     key, QStringLiteral("https://example.com"), "alice",
                     bytes("ReplacementEntryPassword2!")),
                 std::runtime_error);
    expectSameFile(storage.file, original_file);
    auto original_login = original_password;
    const auto entries = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    EXPECT_TRUE(protocol_store.authenticate(entries[0].website,
                                            entries[0].username,
                                            original_login, entries[0].salt));
}

TEST(PasswordVaultWorkflowTest, AuthenticationRejectsChangedEntryAndMissingRecord) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    const auto password = bytes("AuthenticationEntryPassword1!");
    workflow.saveNewCredential(key, QStringLiteral("https://example.com"),
                               "alice", password);
    auto entries = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_TRUE(workflow.authenticate(entries[0]));

    auth::VaultEntry changed_password = entries[0];
    changed_password.password = bytes("WrongAuthenticationPassword2!");
    EXPECT_FALSE(workflow.authenticate(changed_password));
    auth::VaultEntry changed_identity = entries[0];
    changed_identity.username = "different-user";
    EXPECT_FALSE(workflow.authenticate(changed_identity));

    protocol_store.clear();
    EXPECT_FALSE(workflow.authenticate(entries[0]));
}

TEST(PasswordVaultWorkflowTest, UnlockRebuildsV2RecordsWithoutRewritingFile) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    const std::vector<auth::VaultEntry> entries = {
        {"https://saved.example", "saved-user", bytes("SavedEntryPassword1!"),
         std::vector<uint8_t>(16, 0x42)}};
    storage.file = makeVault(storage, key, 2, entries);
    const PasswordVaultFile original_file = storage.file;
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    const auto unlocked = workflow.unlockAndMigrate(key);

    ASSERT_EQ(unlocked.size(), 1u);
    EXPECT_EQ(storage.save_count, 0);
    expectSameFile(storage.file, original_file);
    EXPECT_TRUE(workflow.authenticate(unlocked[0]));
}

TEST(PasswordVaultWorkflowTest, UnlockMigratesV1AndAddsMissingProtocolSalt) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    const std::vector<auth::VaultEntry> entries = {
        {"https://legacy.example", "legacy-user", bytes("LegacyPassword1!"), {}}};
    storage.file = makeVault(storage, key, 1, entries);
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    const auto unlocked = workflow.unlockAndMigrate(key);

    ASSERT_EQ(unlocked.size(), 1u);
    ASSERT_EQ(unlocked[0].salt.size(), auth::kSaltSize);
    EXPECT_EQ(storage.file.format_version, 2);
    EXPECT_EQ(storage.save_count, 1);
    const auto persisted = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0].salt, unlocked[0].salt);
    EXPECT_TRUE(workflow.authenticate(unlocked[0]));
}

TEST(PasswordVaultWorkflowTest, ImportedVaultEntriesMergeAndPersistLatestCredential) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    const auto earlier = std::chrono::system_clock::time_point(std::chrono::seconds(10));
    const auto later = std::chrono::system_clock::time_point(std::chrono::seconds(20));
    storage.file = makeVault(storage, key, 2,
        {{"https://same.example", "alice", bytes("LocalPassword1!"),
          std::vector<uint8_t>(16, 0x21), earlier}});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    const std::vector<auth::VaultEntry> imported = {
        {"https://same.example", "alice", bytes("RemotePassword2!"),
         std::vector<uint8_t>(16, 0x22), later},
        {"https://new.example", "bob", bytes("NewCredential3!"),
         std::vector<uint8_t>(16, 0x23), later}};

    const auto merged = workflow.mergeImportedEntries(key, imported);

    ASSERT_EQ(merged.size(), 2u);
    const auto persisted = auth::DecryptVault(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    ASSERT_EQ(persisted.size(), 2u);
    EXPECT_EQ(persisted[0].password, bytes("RemotePassword2!"));
    EXPECT_TRUE(storage.file.websites.contains(QStringLiteral("https://new.example")));
    auto remote_password = bytes("RemotePassword2!");
    EXPECT_TRUE(protocol_store.authenticate("https://same.example", "alice",
                                             remote_password, persisted[0].salt));
}

TEST(PasswordVaultWorkflowTest, WrongKeyLeavesLegacyFileUnchanged) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 1,
        {{"https://legacy.example", "legacy-user", bytes("LegacyPassword1!"), {}}});
    const PasswordVaultFile original_file = storage.file;
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    EXPECT_THROW(workflow.unlockAndMigrate(std::vector<uint8_t>(32, 0xA5)),
                 std::runtime_error);
    expectSameFile(storage.file, original_file);
    EXPECT_EQ(storage.save_count, 0);
}

TEST(PasswordVaultWorkflowTest, FailedLegacyMigrationSaveLeavesFileAndRecordsUnchanged) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 1,
        {{"https://legacy.example", "legacy-user", bytes("LegacyPassword1!"), {}}});
    const PasswordVaultFile original_file = storage.file;
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    storage.reject_save = true;

    EXPECT_THROW(workflow.unlockAndMigrate(key), std::runtime_error);
    expectSameFile(storage.file, original_file);
    auto password = bytes("LegacyPassword1!");
    EXPECT_FALSE(protocol_store.authenticate("https://legacy.example",
                                             "legacy-user", password,
                                             std::vector<uint8_t>(16, 0x42)));
}

TEST(PasswordVaultWorkflowTest, FailedAddSaveDoesNotPublishProtocolRecord) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    const PasswordVaultFile original_file = storage.file;
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);
    storage.reject_save = true;

    EXPECT_THROW(workflow.saveNewCredential(
                     key, QStringLiteral("https://example.com"), "alice",
                     bytes("FailedSavePassword1!")),
                 std::runtime_error);
    expectSameFile(storage.file, original_file);
    auto password = bytes("FailedSavePassword1!");
    EXPECT_FALSE(protocol_store.authenticate("https://example.com", "alice",
                                             password,
                                             std::vector<uint8_t>(16, 0x42)));
}

}  // namespace
