#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace auth {

/**
 * @brief Represents the payload sent to the server after successful
 * registration.
 */
struct RegistrationPayload {
  std::string username;
  std::vector<uint8_t> encrypted_secret_e;   // Enc(PKs, B)
  std::vector<uint8_t> encrypted_verifier_ed; // Enc(PKs, D)
};

/**
 * @brief Securely registers a user, performing necessary cryptographic
 * operations.
 * @param username The username of the user.
 * @param password The raw password (will be securely cleansed from memory).
 * @param local_db The local database to store the generated Salt (S).
 * @return RegistrationPayload The data to be transmitted to the server.
 */
RegistrationPayload RegisterUser(
    const std::string& username, std::vector<uint8_t>& password,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db);

}  // namespace auth