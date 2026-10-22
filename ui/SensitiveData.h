#pragma once

#include "auth/vault.hpp"

#include <QString>

#include <cstdint>
#include <vector>

namespace ui {

std::vector<std::uint8_t> secureInputBytes(const QString &text);
void wipeBytes(std::vector<std::uint8_t> &bytes) noexcept;
void wipeVaultEntry(auth::VaultEntry &entry) noexcept;
void wipeVaultEntries(std::vector<auth::VaultEntry> &entries) noexcept;

}  // namespace ui
