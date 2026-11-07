#pragma once
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace auth {

struct VaultEntry {
  std::string website;
  std::string username;
  std::vector<uint8_t> password;
  std::vector<uint8_t> salt;
  std::chrono::system_clock::time_point lastModified{std::chrono::system_clock::now()};
};

struct Argon2Params {
  uint32_t memory_cost_kb;
  uint32_t time_cost;
  uint32_t parallelism;
  uint32_t key_length;
};

constexpr Argon2Params kDefaultArgon2Params = {
    65536,  // 64 MB
    3,      // 3 iterations
    4,      // 4 parallel threads
    32      // 256-bit key
};

constexpr size_t kSaltSize = 16;

// AES-256-GCM parameters (exposed for testing)
constexpr size_t kAesGcmIvBytes = 12;
constexpr size_t kAesGcmTagBytes = 16;

std::vector<uint8_t> GenerateSalt();

std::vector<uint8_t> DeriveKey(
    const std::vector<uint8_t>& master_password,
    const std::vector<uint8_t>& salt,
    const Argon2Params& params);

std::vector<uint8_t> EncryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<VaultEntry>& entries);

std::vector<uint8_t> EncryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<VaultEntry>& entries,
    const std::vector<uint8_t>& aad);

std::vector<VaultEntry> DecryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& ciphertext);

std::vector<VaultEntry> DecryptVault(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad);

std::vector<uint8_t> SerializeVault(const std::vector<VaultEntry>& entries);

std::vector<VaultEntry> DeserializeVault(const std::vector<uint8_t>& data);

// Trusted-device list (Protocol 4 VaultSync): each device's TPM signing public key (opaque, variable-length).
// Serialized inside the encrypted vault payload (not in the plaintext index).
// The inner payload is versioned to remain backward compatible with vaults that lack a trust section.
using TrustedDeviceKey = std::vector<uint8_t>;

struct VaultPayload {
  std::vector<VaultEntry> entries;
  std::vector<TrustedDeviceKey> trusted_devices;
};

std::vector<uint8_t> SerializeVaultPayload(const VaultPayload& payload);

VaultPayload DeserializeVaultPayload(const std::vector<uint8_t>& data);

// Raw payload encryption/decryption (used by workflow for trust list operations)
std::vector<uint8_t> EncryptVaultPayload(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext_payload,
    const std::vector<uint8_t>& aad);

std::vector<uint8_t> DecryptVaultPayload(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& ciphertext_blob,
    const std::vector<uint8_t>& aad);

}  // namespace auth
