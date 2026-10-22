#include "../ui/SensitiveData.h"

#include <gtest/gtest.h>

TEST(SensitiveDataTest, ConvertsEmptyAndUnicodeTextToUtf8) {
  EXPECT_TRUE(ui::secureInputBytes(QString()).empty());

  const QString text = QString::fromUtf8("p\xC3\xA4ss\xF0\x9F\x94\x90");
  const std::vector<std::uint8_t> expected = {
      0x70, 0xC3, 0xA4, 0x73, 0x73, 0xF0, 0x9F, 0x94, 0x90};
  EXPECT_EQ(ui::secureInputBytes(text), expected);
}

TEST(SensitiveDataTest, WipesByteBuffers) {
  std::vector<std::uint8_t> bytes = {0x01, 0xA2, 0xFF};
  ui::wipeBytes(bytes);
  EXPECT_TRUE(bytes.empty());
}

TEST(SensitiveDataTest, WipesVaultEntrySensitiveFields) {
  auth::VaultEntry first;
  first.website = "example.com";
  first.username = "alice";
  first.password = {0x01, 0x02};
  first.salt = {0x03, 0x04};
  auth::VaultEntry second;
  second.website = "example.org";
  second.username = "bob";
  second.password = {0x05};
  second.salt = {0x06};
  ui::wipeVaultEntry(first);
  EXPECT_TRUE(first.website.empty());
  EXPECT_TRUE(first.username.empty());
  EXPECT_TRUE(first.password.empty());
  EXPECT_TRUE(first.salt.empty());

  std::vector<auth::VaultEntry> entries = {second};
  ui::wipeVaultEntries(entries);
  EXPECT_TRUE(entries.empty());
}
