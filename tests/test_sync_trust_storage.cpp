// Trust store TDD tests for Protocol 4 VaultSync trusted-device list T.
// T lives inside the encrypted vault payload, not in the plaintext index.

#include "PasswordVaultFileStore.h"
#include "PasswordVaultWorkflow.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

namespace {

// Minimal in-memory storage for unit tests (copied from test_password_manager_workflow.cpp)
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

std::vector<uint8_t> bytes(size_t n, uint8_t val) {
    return std::vector<uint8_t>(n, val);
}

// Helper: construct a vault with a given key and entries (no trust list API used)
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

// Helper: get the decrypted entries from a vault file
std::vector<auth::VaultEntry> decryptEntries(const MemoryVaultStorage &storage,
                                             const std::vector<uint8_t> &key) {
    std::vector<uint8_t> plaintext = auth::DecryptVaultPayload(
        key, storage.file.ciphertext, storage.authenticatedData(storage.file));
    auth::VaultPayload payload = auth::DeserializeVaultPayload(plaintext);
    return payload.entries;
}

// Helper to check if a key is in the trusted list
bool isTrusted(const std::vector<auth::TrustedDeviceKey> &trusted,
               const std::vector<uint8_t> &key) {
    return std::find(trusted.begin(), trusted.end(), key) != trusted.end();
}

// Test 1: A vault with trusted device keys round-trips through EncryptVault->DecryptVault
TEST(SyncTrustStoreTest, TrustListRoundTripsWithTwoKeys) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    // Add two trusted device keys (opaque arbitrary-length bytes, like ML-DSA-65 ~1.5KB)
    std::vector<uint8_t> key1 = bytes("pkdev-1");
    std::vector<uint8_t> key2 = bytes("pkdev-2-longer-key-material-for-ml-dsa-65-simulation");

    workflow.addTrustedDevice(key, key1);
    workflow.addTrustedDevice(key, key2);

    // Re-read from storage
    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_EQ(trusted.size(), 2u);
    EXPECT_TRUE(isTrusted(trusted, key1));
    EXPECT_TRUE(isTrusted(trusted, key2));

    // Also verify entries are intact
    auto entries = decryptEntries(storage, key);
    EXPECT_TRUE(entries.empty());
}

// Test 2: Migration - old payload without trust section decrypts to empty trust list
TEST(SyncTrustStoreTest, OldPayloadWithoutTrustSectionLoadsEmptyTrustList) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;

    // Manually construct a v2-format vault using current EncryptVault (no trust section)
    std::vector<auth::VaultEntry> entries = {
        {"https://example.com", "alice", bytes("secret1"), bytes(16, 0x01),
         std::chrono::system_clock::now()}
    };
    storage.file = makeVault(storage, key, 2, entries);

    // Now read it back using the new API (which should understand trust list)
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    const auto decrypted = decryptEntries(storage, key);
    ASSERT_EQ(decrypted.size(), 1u);
    EXPECT_EQ(decrypted[0].website, "https://example.com");

    // Trust list should be empty for old payloads
    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_TRUE(trusted.empty());
}

// Test 3: add is idempotent (add same key twice -> one copy)
TEST(SyncTrustStoreTest, AddTrustedDeviceIsIdempotent) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    std::vector<uint8_t> key1 = bytes("pkdev-idempotent-test");

    workflow.addTrustedDevice(key, key1);
    workflow.addTrustedDevice(key, key1);  // second add

    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_EQ(trusted.size(), 1u);
    EXPECT_TRUE(isTrusted(trusted, key1));
}

// Test 4: revoke removes exactly one key and returns true; revoking absent key returns false
TEST(SyncTrustStoreTest, RevokeTrustedDeviceRemovesKey) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    std::vector<uint8_t> key1 = bytes("pkdev-revoke-test-1");
    std::vector<uint8_t> key2 = bytes("pkdev-revoke-test-2");

    workflow.addTrustedDevice(key, key1);
    workflow.addTrustedDevice(key, key2);

    // Revoke key1
    bool removed1 = workflow.revokeTrustedDevice(key, key1);
    EXPECT_TRUE(removed1);
    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_EQ(trusted.size(), 1u);
    EXPECT_FALSE(isTrusted(trusted, key1));
    EXPECT_TRUE(isTrusted(trusted, key2));

    // Revoke absent key
    bool removed2 = workflow.revokeTrustedDevice(key, key1);
    EXPECT_FALSE(removed2);
    trusted = workflow.listTrustedDevices(key);
    EXPECT_EQ(trusted.size(), 1u);
}

// Test 5: Empty trust list round-trips
TEST(SyncTrustStoreTest, EmptyTrustListRoundTrips) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    // Don't add any keys
    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_TRUE(trusted.empty());

    // Re-save and re-read (simulate saveNewCredential or similar)
    workflow.saveNewCredential(key, "https://example.com", "user", bytes("pass"));

    trusted = workflow.listTrustedDevices(key);
    EXPECT_TRUE(trusted.empty());
}

// Test 6: Keys are opaque arbitrary-length: test 1-byte, ~1.5KB, and prefix confusion
TEST(SyncTrustStoreTest, KeysAreOpaqueArbitraryLengthAndPrefixSafe) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    // 1-byte key
    std::vector<uint8_t> key1 = {0x42};
    // ~1.5KB key (ML-DSA-65 size)
    std::vector<uint8_t> key2(1500, 0xAA);
    key2[0] = 0x42;  // Make key2 start with same byte as key1 (prefix test)
    // Another distinct key
    std::vector<uint8_t> key3 = {0x43};

    workflow.addTrustedDevice(key, key1);
    workflow.addTrustedDevice(key, key2);
    workflow.addTrustedDevice(key, key3);

    auto trusted = workflow.listTrustedDevices(key);
    EXPECT_EQ(trusted.size(), 3u);
    EXPECT_TRUE(isTrusted(trusted, key1));
    EXPECT_TRUE(isTrusted(trusted, key2));
    EXPECT_TRUE(isTrusted(trusted, key3));
}

// Test 7: Tampered/corrupt trust section fails closed (throws/decrypt fails)
TEST(SyncTrustStoreTest, CorruptTrustSectionFailsClosed) {
    const std::vector<uint8_t> key(32, 0x5A);
    MemoryVaultStorage storage;
    storage.file = makeVault(storage, key, 2, {});
    auth::WebsiteCredentialAuthStore protocol_store;
    PasswordVaultWorkflow workflow(storage, protocol_store);

    // Add a trusted device
    std::vector<uint8_t> key1 = bytes("pkdev-corrupt-test");
    workflow.addTrustedDevice(key, key1);

    // Now corrupt the ciphertext by flipping a byte in the middle
    // We need to corrupt the encrypted payload (not the IV or tag)
    const size_t overhead = auth::kAesGcmIvBytes + auth::kAesGcmTagBytes;
    ASSERT_GT(storage.file.ciphertext.size(), overhead + 10);
    // Corrupt a byte in the ciphertext portion
    storage.file.ciphertext[overhead + 5] ^= 0xFF;

    // Attempt to read the trust list - should throw
    EXPECT_THROW(workflow.listTrustedDevices(key), std::runtime_error);
}

} // namespace
