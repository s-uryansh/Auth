#include "auth/WebsiteCredentialAuth.hpp"

#include <openssl/crypto.h>

#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "auth/Authentication.hpp"
#include "auth/vault.hpp"

namespace auth {
namespace {

void appendLengthPrefixed(std::string& output, const std::string& value) {
  if (value.size() > std::numeric_limits<uint32_t>::max()) {
    throw std::length_error("Website credential identity component is too long");
  }
  const auto length = static_cast<uint32_t>(value.size());
  output.push_back(static_cast<char>((length >> 24) & 0xff));
  output.push_back(static_cast<char>((length >> 16) & 0xff));
  output.push_back(static_cast<char>((length >> 8) & 0xff));
  output.push_back(static_cast<char>(length & 0xff));
  output.append(value);
}

class WipeOnExit {
public:
  explicit WipeOnExit(std::vector<uint8_t>& value) : value_(value) {}
  ~WipeOnExit() { OPENSSL_cleanse(value_.data(), value_.size()); }

  WipeOnExit(const WipeOnExit&) = delete;
  WipeOnExit& operator=(const WipeOnExit&) = delete;

private:
  std::vector<uint8_t>& value_;
};

}  // namespace

std::string WebsiteCredentialAuthStore::identity(
    const std::string& website,
    const std::string& username) {
  std::string result;
  result.reserve(8 + website.size() + username.size());
  appendLengthPrefixed(result, website);
  appendLengthPrefixed(result, username);
  return result;
}

RegistrationPayload WebsiteCredentialAuthStore::prepareRegistration(
    const std::string& website,
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt) const {
  if (salt.size() != kSaltSize) {
    throw std::runtime_error("Website protocol salt must be exactly 16 bytes");
  }

  const std::string user_identity = identity(website, username);
  std::unordered_map<std::string, std::vector<uint8_t>> local_salts;
  RegistrationPayload record =
      RegisterUserWithSalt(user_identity, password, salt, local_salts);
  if (record.username != user_identity ||
      local_salts.find(user_identity) == local_salts.end() ||
      local_salts.at(user_identity) != salt) {
    throw std::runtime_error("Protocol 1 returned an inconsistent credential record");
  }
  return record;
}

void WebsiteCredentialAuthStore::commitRegistration(
    const RegistrationPayload& record) {
  commitRegistrations({record});
}

void WebsiteCredentialAuthStore::commitRegistrations(
    const std::vector<RegistrationPayload>& records) {
  std::unordered_set<std::string> new_identities;
  new_identities.reserve(records.size());
  for (const RegistrationPayload& record : records) {
    if (record.username.empty() || records_.count(record.username) != 0 ||
        !new_identities.insert(record.username).second) {
      throw std::runtime_error("Website credential protocol identity already exists");
    }
  }

  auto updated_records = records_;
  updated_records.reserve(updated_records.size() + records.size());
  for (const RegistrationPayload& record : records) {
    updated_records.emplace(record.username, record);
  }
  records_.swap(updated_records);
}

bool WebsiteCredentialAuthStore::authenticate(
    const std::string& website,
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt) const {
  if (salt.size() != kSaltSize) return false;

  const std::string user_identity = identity(website, username);
  const auto record = records_.find(user_identity);
  if (record == records_.end() || record->second.username != user_identity) {
    return false;
  }

  std::vector<uint8_t> password_copy = password;
  WipeOnExit wipe_password(password_copy);
  return AuthenticateUser(user_identity, password_copy, salt, record->second);
}

void WebsiteCredentialAuthStore::clear() {
  records_.clear();
}

}  // namespace auth
