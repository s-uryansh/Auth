#include "auth/vault.hpp"
#include "PasswordVaultFileStore.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtEndian>

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

auth::VaultEntry makeEntry(const std::string &website,
                           const std::string &username,
                           std::vector<std::uint8_t> password,
                           std::vector<std::uint8_t> salt) {
    return {website, username, std::move(password), std::move(salt)};
}

PasswordVaultFile makeVaultFile() {
    PasswordVaultFile vault;
    vault.salt = std::vector<std::uint8_t>(auth::kSaltSize, 0x31);
    vault.params = auth::kDefaultArgon2Params;
    vault.ciphertext = std::vector<std::uint8_t>(28, 0x42);
    vault.websites = {"https://example.com", "https://example.org"};
    return vault;
}

void replaceBigEndian32(QByteArray &bytes, qsizetype offset, quint32 value) {
    qToBigEndian(value, reinterpret_cast<uchar *>(bytes.data() + offset));
}

} // namespace

TEST(VaultCoreTest, GeneratedSaltHasVaultSaltLength) {
    EXPECT_EQ(auth::GenerateSalt().size(), auth::kSaltSize);
}

TEST(VaultCoreTest, GeneratedSaltsAreIndependent) {
    EXPECT_NE(auth::GenerateSalt(), auth::GenerateSalt());
}

TEST(VaultCoreTest, ArgonKeyUsesRequestedLengthAndChangesWithInputs) {
    const std::vector<std::uint8_t> password = {'m', 'a', 's', 't', 'e', 'r'};
    const std::vector<std::uint8_t> salt_a(16, 0x11);
    const std::vector<std::uint8_t> salt_b(16, 0x12);
    auth::Argon2Params params{1024, 1, 1, 24};

    const auto key = auth::DeriveKey(password, salt_a, params);
    EXPECT_EQ(key.size(), 24u);
    EXPECT_EQ(key, auth::DeriveKey(password, salt_a, params));
    EXPECT_NE(key, auth::DeriveKey(password, salt_b, params));
    EXPECT_NE(key, auth::DeriveKey({'m', 'a', 's', 't', 'e', 'R'}, salt_a,
                                   params));
}

TEST(VaultCoreTest, ArgonRejectsInvalidParameters) {
    const std::vector<std::uint8_t> password = {'p'};
    const std::vector<std::uint8_t> salt(16, 0x22);
    auth::Argon2Params params = auth::kDefaultArgon2Params;
    params.time_cost = 0;
    EXPECT_THROW(auth::DeriveKey(password, salt, params), std::runtime_error);

    params = auth::kDefaultArgon2Params;
    params.key_length = 0;
    EXPECT_THROW(auth::DeriveKey(password, salt, params), std::runtime_error);
}

TEST(VaultSerializationTest, EmptyVaultRoundTrips) {
    const std::vector<auth::VaultEntry> empty;
    const std::vector<std::uint8_t> expected = {0, 0, 0, 0};
    EXPECT_EQ(auth::SerializeVault(empty), expected);
    EXPECT_TRUE(auth::DeserializeVault(expected).empty());
}

TEST(VaultSerializationTest, MultipleBinaryEntriesRoundTrip) {
    const std::vector<auth::VaultEntry> entries = {
        makeEntry("https://example.com", "alice", {0x00, 0xFF, 0x41}, {1, 2}),
        makeEntry("", "", {}, {})};
    const auto encoded = auth::SerializeVault(entries);
    const auto decoded = auth::DeserializeVault(encoded);

    ASSERT_EQ(decoded.size(), 2u);
    EXPECT_EQ(decoded[0].website, entries[0].website);
    EXPECT_EQ(decoded[0].username, entries[0].username);
    EXPECT_EQ(decoded[0].password, entries[0].password);
    EXPECT_EQ(decoded[0].salt, entries[0].salt);
    EXPECT_EQ(decoded[1].website, "");
    EXPECT_EQ(decoded[1].username, "");
    EXPECT_TRUE(decoded[1].password.empty());
    EXPECT_TRUE(decoded[1].salt.empty());
}

TEST(VaultSerializationTest, RejectsTruncatedCountAndFields) {
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0}), std::runtime_error);
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0, 1}), std::runtime_error);
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0, 1, 0, 0}),
                 std::runtime_error);
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0, 1, 0, 0, 0, 2, 'x'}),
                 std::runtime_error);
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}),
                 std::runtime_error);
}

TEST(VaultSerializationTest, RejectsEntryCountThatCannotFitInput) {
    EXPECT_THROW(auth::DeserializeVault({0xFF, 0xFF, 0xFF, 0xFF}),
                 std::runtime_error);
}

TEST(VaultSerializationTest, RejectsTrailingSerializedBytes) {
    EXPECT_THROW(auth::DeserializeVault({0, 0, 0, 0, 0x99}),
                 std::runtime_error);
}

TEST(VaultCryptoTest, EncryptsAndDecryptsEmptyVault) {
    const std::vector<std::uint8_t> key(32, 0x5A);
    const std::vector<auth::VaultEntry> empty;
    const auto ciphertext = auth::EncryptVault(key, empty);
    EXPECT_EQ(ciphertext.size(), 32u);
    EXPECT_TRUE(auth::DecryptVault(key, ciphertext).empty());
}

TEST(VaultCryptoTest, EncryptsAndDecryptsMultipleEntries) {
    const std::vector<std::uint8_t> key(32, 0x5A);
    const std::vector<auth::VaultEntry> entries = {
        makeEntry("https://example.com", "alice", {0x00, 0xFF}, {1, 2}),
        makeEntry("https://example.org", "bob", {3, 4, 5}, {6})};
    const auto ciphertext = auth::EncryptVault(key, entries);
    const auto decrypted = auth::DecryptVault(key, ciphertext);
    ASSERT_EQ(decrypted.size(), entries.size());
    EXPECT_EQ(decrypted[0].website, entries[0].website);
    EXPECT_EQ(decrypted[0].username, entries[0].username);
    EXPECT_EQ(decrypted[0].password, entries[0].password);
    EXPECT_EQ(decrypted[0].salt, entries[0].salt);
    EXPECT_EQ(decrypted[1].website, entries[1].website);
    EXPECT_EQ(decrypted[1].username, entries[1].username);
    EXPECT_EQ(decrypted[1].password, entries[1].password);
    EXPECT_EQ(decrypted[1].salt, entries[1].salt);
}

TEST(VaultCryptoTest, RejectsWrongKeyAndTamperedCiphertext) {
    const std::vector<std::uint8_t> key(32, 0x5A);
    const std::vector<auth::VaultEntry> entries = {
        makeEntry("site", "user", {1, 2, 3}, {4})};
    const auto ciphertext = auth::EncryptVault(key, entries);

    EXPECT_THROW(auth::DecryptVault(std::vector<std::uint8_t>(32, 0xA5),
                                    ciphertext), std::runtime_error);
    for (const std::size_t index : {0u, 12u, 28u}) {
        auto damaged = ciphertext;
        damaged[index] ^= 0x01;
        EXPECT_THROW(auth::DecryptVault(key, damaged), std::runtime_error);
    }
}

TEST(VaultCryptoTest, RejectsTruncatedCiphertextAndInvalidKeyLengths) {
    const std::vector<std::uint8_t> key(32, 0x5A);
    for (std::size_t length : {0u, 1u, 27u, 28u, 31u}) {
        EXPECT_THROW(auth::DecryptVault(key,
                       std::vector<std::uint8_t>(length, 0)), std::runtime_error);
    }
    const std::vector<auth::VaultEntry> entries;
    const auto valid_ciphertext = auth::EncryptVault(key, entries);
    for (std::size_t length : {0u, 31u, 33u}) {
        const std::vector<std::uint8_t> invalid_key(length, 0);
        EXPECT_THROW(auth::EncryptVault(invalid_key, entries), std::runtime_error);
        EXPECT_THROW(auth::DecryptVault(invalid_key, valid_ciphertext),
                     std::runtime_error);
    }
}

TEST(PasswordVaultFileStoreTest, SavesAndLoadsVaultMetadataAndWebsiteIndex) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath("vault with spaces.dat");
    const PasswordVaultFileStore store(path);
    EXPECT_FALSE(store.exists());

    const PasswordVaultFile expected = makeVaultFile();
    store.save(expected);
    ASSERT_TRUE(store.exists());
    const PasswordVaultFile loaded = store.load();
    EXPECT_EQ(loaded.salt, expected.salt);
    EXPECT_EQ(loaded.params.memory_cost_kb, expected.params.memory_cost_kb);
    EXPECT_EQ(loaded.params.time_cost, expected.params.time_cost);
    EXPECT_EQ(loaded.params.parallelism, expected.params.parallelism);
    EXPECT_EQ(loaded.params.key_length, expected.params.key_length);
    EXPECT_EQ(loaded.ciphertext, expected.ciphertext);
    EXPECT_EQ(loaded.websites, expected.websites);
}

TEST(PasswordVaultFileStoreTest, MissingAndEmptyFilesAreRejected) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath("missing.dat");
    const PasswordVaultFileStore store(path);
    EXPECT_THROW(store.load(), std::runtime_error);

    QFile empty_file(directory.filePath("empty.dat"));
    ASSERT_TRUE(empty_file.open(QIODevice::WriteOnly));
    empty_file.close();
    EXPECT_THROW(PasswordVaultFileStore(empty_file.fileName()).load(),
                 std::runtime_error);
}

TEST(PasswordVaultFileStoreTest, RejectsCorruptHeaderTruncationAndTrailingBytes) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath("vault.dat");
    PasswordVaultFileStore store(path);
    store.save(makeVaultFile());

    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::ReadWrite));
    ASSERT_EQ(file.read(1).size(), 1);
    ASSERT_TRUE(file.seek(0));
    ASSERT_EQ(file.write("X", 1), 1);
    file.close();
    EXPECT_THROW(store.load(), std::runtime_error);

    store.save(makeVaultFile());
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(file.write("AUTH", 4), 4);
    file.close();
    EXPECT_THROW(store.load(), std::runtime_error);

    store.save(makeVaultFile());
    ASSERT_TRUE(file.open(QIODevice::Append));
    ASSERT_EQ(file.write("x", 1), 1);
    file.close();
    EXPECT_THROW(store.load(), std::runtime_error);
}

TEST(PasswordVaultFileStoreTest, RejectsInvalidMetadataAndWebsiteEntries) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    PasswordVaultFileStore store(directory.filePath("vault.dat"));
    PasswordVaultFile vault = makeVaultFile();

    vault.salt.pop_back();
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.params.time_cost++;
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.params.memory_cost_kb++;
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.params.parallelism++;
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.params.key_length++;
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.ciphertext.resize(27);
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.websites = {""};
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.websites = {QString(4097, QLatin1Char('x'))};
    EXPECT_THROW(store.save(vault), std::runtime_error);
    vault = makeVaultFile();
    vault.websites = QStringList(10001, QStringLiteral("https://example.com"));
    EXPECT_THROW(store.save(vault), std::runtime_error);
}

TEST(PasswordVaultFileStoreTest, RejectsMalformedEncodedLengths) {
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath("vault.dat");
    PasswordVaultFileStore store(path);
    const PasswordVaultFile valid = makeVaultFile();
    store.save(valid);

    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    const QByteArray original = file.readAll();
    file.close();
    ASSERT_EQ(original.size(), 162);

    const std::vector<std::pair<qsizetype, quint32>> bad_lengths = {
        {22, 15},       // salt must be exactly 16 bytes
        {42, 10001},    // website index count limit
        {46, 0},        // first website may not be empty
        {46, 3},        // UTF-16 byte length must be even
        {130, 27}};     // AES-GCM framing minimum
    for (const auto &[offset, value] : bad_lengths) {
        QByteArray damaged = original;
        replaceBigEndian32(damaged, offset, value);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(file.write(damaged), damaged.size());
        file.close();
        EXPECT_THROW(store.load(), std::runtime_error)
            << "malformed length at byte " << offset << " value " << value;
    }
}

