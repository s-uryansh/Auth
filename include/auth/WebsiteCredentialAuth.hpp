#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Registration.hpp"

namespace auth {

// In-process Protocol 1/2 record store for the Password Manager prototype.
// Records intentionally disappear when the application exits.
class WebsiteCredentialAuthStore {
public:
  // Encodes the already-normalized website URL and username as two
  // length-prefixed byte strings, avoiding ambiguous concatenations.
  static std::string identity(const std::string& website,
                              const std::string& username);

  // Creates a Protocol 1 record without publishing it to this store.
  // RegisterUserWithSalt wipes password; callers should pass a temporary copy.
  RegistrationPayload prepareRegistration(
      const std::string& website,
      const std::string& username,
      std::vector<uint8_t>& password,
      const std::vector<uint8_t>& salt) const;

  // Publishes one record. Duplicate identities are rejected.
  void commitRegistration(const RegistrationPayload& record);

  // Validates the whole batch before publishing any record.
  void commitRegistrations(const std::vector<RegistrationPayload>& records);

  // Verifies a credential against the matching in-process Protocol 1 record.
  // Returns false for missing records and invalid salt lengths. The supplied
  // password is not modified; a temporary copy is wiped after verification.
  bool authenticate(const std::string& website,
                    const std::string& username,
                    std::vector<uint8_t>& password,
                    const std::vector<uint8_t>& salt) const;

  void clear();

private:
  std::unordered_map<std::string, RegistrationPayload> records_;
};

}  // namespace auth
