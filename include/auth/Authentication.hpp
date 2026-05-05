#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "auth/Registration.hpp"

namespace auth {

/**
 * @brief CLIENT-SIDE: Hashes password with salt to produce C = H(S, P).
 * @param stored_salt The 128-bit salt retrieved from local UserDB.
 * @param password The raw password (will be securely cleansed from memory).
 * @return Hash C = H(S, P) as a byte vector.
 */
std::vector<uint8_t> ComputeClientHash(const std::vector<uint8_t>& stored_salt,
                                       std::vector<uint8_t>& password);

/**
 * @brief SERVER-SIDE: Verifies authentication given C and the stored record.
 * Decrypts E->B, ED->D, recomputes D'=HMAC_B(C), compares D==D'.
 * @param username Used to validate server_record.username matches.
 * @param hash_c The client-computed hash C = H(S, P).
 * @param server_record The {U, E, ED} tuple from ServerDB.
 * @return true if D == D', false otherwise.
 */
bool VerifyOnServer(const std::string& username,
                    std::vector<uint8_t>& hash_c,
                    const RegistrationPayload& server_record);

/**
 * @brief Full authentication flow (client hash + server verify).
 * Convenience wrapper combining ComputeClientHash and VerifyOnServer.
 * @param username The user's identifier.
 * @param password The raw password (will be securely cleansed from memory).
 * @param stored_salt The 128-bit salt retrieved from local UserDB.
 * @param server_record The {U, E, ED} tuple from ServerDB.
 * @return true if authentication succeeds, false otherwise.
 */
bool AuthenticateUser(const std::string& username,
                      std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& stored_salt,
                      const RegistrationPayload& server_record);

}  // namespace auth