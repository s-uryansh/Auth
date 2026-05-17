#pragma once

#include <string>
#include <vector>

#include "auth/Registration.hpp"

namespace auth {

// Protocol 2 — Authentication, client side.
//
// Computes C ← H(S, P) and immediately wipes P.
//
// @param stored_salt  Salt S retrieved from the local device DB.
// @param password     Plaintext password bytes P (wiped on return).
// @returns            Hash C = H(S, P).
std::vector<uint8_t> ComputeClientHash(const std::vector<uint8_t>& stored_salt,
                                       std::vector<uint8_t>& password);

// Protocol 2 — Authentication, server side.
//
// New flow (updated protocol):
//   1. Decrypt E  → B⊕R  using SKs.
//   2. Recover B  = (B⊕R) ⊕ R  using the stored server nonce R.
//   3. Decrypt ED → D    using SKs.
//   4. Recompute D' = HMAC_B(C).
//   5. Authenticate iff D == D'  (constant-time compare).
//   6. Wipe all intermediates.
//
// @param username       Username U (guards against API misuse).
// @param hash_c         Client hash C (wiped on return).
// @param server_record  RegistrationPayload {U, E, ED, R} from server DB.
// @returns              true iff authentication succeeds.
bool VerifyOnServer(const std::string& username, std::vector<uint8_t>& hash_c,
                    const RegistrationPayload& server_record);

// Convenience wrapper: ComputeClientHash + VerifyOnServer in one call.
//
// @param username       Username U.
// @param password       Plaintext password bytes P (wiped on return).
// @param stored_salt    Salt S from device-local DB.
// @param server_record  RegistrationPayload from server DB.
// @returns              true iff authentication succeeds.
bool AuthenticateUser(const std::string& username,
                      std::vector<uint8_t>& password,
                      const std::vector<uint8_t>& stored_salt,
                      const RegistrationPayload& server_record);

}  // namespace auth