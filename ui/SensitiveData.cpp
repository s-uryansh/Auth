#include "SensitiveData.h"

#include <QByteArray>

#include <openssl/crypto.h>

namespace ui {
namespace {

void cleanseString(std::string &text) noexcept {
  if (!text.empty()) {
    OPENSSL_cleanse(text.data(), text.size());
    text.clear();
  }
}

}  // namespace

std::vector<std::uint8_t> secureInputBytes(const QString &text) {
  QByteArray utf8 = text.toUtf8();
  std::vector<std::uint8_t> bytes(utf8.begin(), utf8.end());
  if (!utf8.isEmpty()) {
    OPENSSL_cleanse(utf8.data(), static_cast<std::size_t>(utf8.size()));
  }
  return bytes;
}

void wipeBytes(std::vector<std::uint8_t> &bytes) noexcept {
  if (!bytes.empty()) {
    OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
  }
}

void wipeVaultEntry(auth::VaultEntry &entry) noexcept {
  cleanseString(entry.website);
  cleanseString(entry.username);
  wipeBytes(entry.password);
  wipeBytes(entry.salt);
}

void wipeVaultEntries(std::vector<auth::VaultEntry> &entries) noexcept {
  for (auth::VaultEntry &entry : entries) wipeVaultEntry(entry);
  entries.clear();
}

}  // namespace ui
