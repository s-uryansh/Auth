#include "PasswordVaultFileStore.h"

#include <QDataStream>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QtEndian>

#include <stdexcept>
#include <utility>

namespace {

constexpr quint32 kVaultFileMagic = 0x41555448; // "AUTH"
constexpr quint16 kVaultFileVersion = 1;
constexpr qint64 kMaximumVaultFileSize = 64 * 1024 * 1024;
constexpr quint32 kMaximumWebsiteCount = 10000;
constexpr qsizetype kMaximumWebsiteLength = 4096;
constexpr quint32 kMaximumCiphertextSize =
    static_cast<quint32>(kMaximumVaultFileSize);

void configureStream(QDataStream &stream) {
    stream.setVersion(QDataStream::Qt_6_0);
    stream.setByteOrder(QDataStream::BigEndian);
}

QByteArray toByteArray(const std::vector<uint8_t> &bytes) {
    return QByteArray(reinterpret_cast<const char *>(bytes.data()),
                      static_cast<qsizetype>(bytes.size()));
}

std::vector<uint8_t> toBytes(const QByteArray &bytes) {
    if (bytes.isEmpty()) return {};
    const auto *begin = reinterpret_cast<const uint8_t *>(bytes.constData());
    return {begin, begin + bytes.size()};
}

bool readLength(const QByteArray &bytes, qsizetype &offset, quint32 &length) {
    if (offset < 0 || bytes.size() - offset < 4) return false;
    length = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar *>(bytes.constData() + offset));
    offset += 4;
    return true;
}

void validateEncodedLengths(const QByteArray &bytes) {
    qsizetype offset = 22; // magic, version, and four KDF parameters
    quint32 salt_length = 0;
    if (!readLength(bytes, offset, salt_length) || salt_length != auth::kSaltSize ||
        bytes.size() - offset < static_cast<qsizetype>(salt_length)) {
        throw std::runtime_error("Password vault salt encoding is invalid");
    }
    offset += static_cast<qsizetype>(salt_length);

    quint32 website_count = 0;
    if (bytes.size() - offset < 4) {
        throw std::runtime_error("Password vault website index is truncated");
    }
    website_count = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar *>(bytes.constData() + offset));
    offset += 4;
    if (website_count > kMaximumWebsiteCount) {
        throw std::runtime_error("Password vault website index is too large");
    }

    for (quint32 i = 0; i < website_count; ++i) {
        quint32 encoded_bytes = 0;
        if (!readLength(bytes, offset, encoded_bytes) || encoded_bytes == 0 ||
            encoded_bytes > static_cast<quint32>(kMaximumWebsiteLength * 2) ||
            encoded_bytes % 2 != 0 ||
            bytes.size() - offset < static_cast<qsizetype>(encoded_bytes)) {
            throw std::runtime_error("Password vault website encoding is invalid");
        }
        offset += static_cast<qsizetype>(encoded_bytes);
    }

    quint32 ciphertext_length = 0;
    if (!readLength(bytes, offset, ciphertext_length) || ciphertext_length < 28 ||
        ciphertext_length > kMaximumCiphertextSize ||
        bytes.size() - offset != static_cast<qsizetype>(ciphertext_length)) {
        throw std::runtime_error("Password vault ciphertext encoding is invalid");
    }
}

void validateVault(const PasswordVaultFile &vault) {
    const auth::Argon2Params &supported = auth::kDefaultArgon2Params;
    if (vault.salt.size() != auth::kSaltSize ||
        vault.params.key_length != supported.key_length ||
        vault.params.memory_cost_kb != supported.memory_cost_kb ||
        vault.params.time_cost != supported.time_cost ||
        vault.params.parallelism != supported.parallelism ||
        vault.ciphertext.size() < 28 ||
        vault.websites.size() > static_cast<qsizetype>(kMaximumWebsiteCount)) {
        throw std::runtime_error("Invalid password vault metadata");
    }

    for (const QString &website : vault.websites) {
        if (website.isEmpty() || website.size() > kMaximumWebsiteLength) {
            throw std::runtime_error("Invalid website index entry");
        }
    }
}

} // namespace

PasswordVaultFileStore::PasswordVaultFileStore(QString filePath)
    : file_path_(std::move(filePath)) {}

bool PasswordVaultFileStore::exists() const {
    return QFileInfo::exists(file_path_);
}

PasswordVaultFile PasswordVaultFileStore::load() const {
    const QFileInfo info(file_path_);
    if (!info.exists() || !info.isFile() || info.size() <= 0 ||
        info.size() > kMaximumVaultFileSize) {
        throw std::runtime_error("Password vault file is missing or invalid");
    }

    QFile file(file_path_);
    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Could not open password vault file");
    }

    const QByteArray contents = file.readAll();
    if (file.error() != QFile::NoError || contents.isEmpty() ||
        contents.size() > kMaximumVaultFileSize) {
        throw std::runtime_error("Could not read password vault file");
    }
    validateEncodedLengths(contents);

    QDataStream stream(contents);
    configureStream(stream);
    quint32 magic = 0;
    quint16 version = 0;
    quint32 memory_cost_kb = 0;
    quint32 time_cost = 0;
    quint32 parallelism = 0;
    quint32 key_length = 0;
    QByteArray salt;
    quint32 website_count = 0;

    stream >> magic >> version >> memory_cost_kb >> time_cost >> parallelism
           >> key_length >> salt >> website_count;
    if (stream.status() != QDataStream::Ok || magic != kVaultFileMagic ||
        version != kVaultFileVersion || website_count > kMaximumWebsiteCount) {
        throw std::runtime_error("Password vault file header is invalid");
    }

    PasswordVaultFile vault;
    vault.salt = toBytes(salt);
    vault.params = {memory_cost_kb, time_cost, parallelism, key_length};
    vault.websites.reserve(static_cast<qsizetype>(website_count));

    for (quint32 i = 0; i < website_count; ++i) {
        QString website;
        stream >> website;
        if (stream.status() != QDataStream::Ok || website.isEmpty() ||
            website.size() > kMaximumWebsiteLength) {
            throw std::runtime_error("Password vault website index is invalid");
        }
        vault.websites.push_back(std::move(website));
    }

    QByteArray ciphertext;
    stream >> ciphertext;
    if (stream.status() != QDataStream::Ok || !file.atEnd()) {
        throw std::runtime_error("Password vault file is truncated or has trailing data");
    }
    vault.ciphertext = toBytes(ciphertext);
    validateVault(vault);
    return vault;
}

void PasswordVaultFileStore::save(const PasswordVaultFile &vault) const {
    validateVault(vault);

    QSaveFile file(file_path_);
    if (!file.open(QIODevice::WriteOnly)) {
        throw std::runtime_error("Could not create password vault file");
    }

    QDataStream stream(&file);
    configureStream(stream);
    stream << kVaultFileMagic << kVaultFileVersion
           << vault.params.memory_cost_kb << vault.params.time_cost
           << vault.params.parallelism << vault.params.key_length
           << toByteArray(vault.salt)
           << static_cast<quint32>(vault.websites.size());
    for (const QString &website : vault.websites) {
        stream << website;
    }
    stream << toByteArray(vault.ciphertext);

    if (stream.status() != QDataStream::Ok || !file.commit()) {
        throw std::runtime_error("Could not save password vault file");
    }
}
