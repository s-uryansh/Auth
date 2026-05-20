#pragma once

#include <string>
#include <vector>

#include "auth/Registration.hpp"

namespace auth {

// ── ComputeClientHash ─────────────────────────────────────────────────────────
//
// Protocol 2, client side: C ← H(S, P).
// Password P is wiped immediately after hashing.
//
// @param stored_salt  Salt S from device-local DB (16 bytes).
// @param password     Plaintext P — zeroed on return.
// @returns            32-byte SHA-256 hash C = H(S ‖ P).
std::vector<uint8_t> ComputeClientHash(
    const std::vector<uint8_t>& stored_salt,
    std::vector<uint8_t>& password);

// ── VerifyOnServer ────────────────────────────────────────────────────────────
//
// Protocol 2, server side.
//
// Steps:
//   1. B⊕R ← HybridDec(SKs, E)
//   2. B    = (B⊕R) ⊕ R          (using server_record.server_nonce_r)
//   3. D    ← HybridDec(SKs, ED)
//   4. D'   ← HMAC_B(C)
//   5. Authenticate iff CRYPTO_memcmp(D, D') == 0
//   6. Wipe all intermediates.
//
// @param username       Identity U (guards against record mix-up).
// @param hash_c         Client hash C — zeroed on return.
// @param server_record  RegistrationPayload {U, E, ED, R} from server DB.
// @returns              true iff authentication succeeds.
bool VerifyOnServer(
    const std::string& username,
    std::vector<uint8_t>& hash_c,
    const RegistrationPayload& server_record);

// ── AuthenticateUser ──────────────────────────────────────────────────────────
//
// Convenience wrapper: ComputeClientHash → VerifyOnServer.
//
// @param username       Identity U.
// @param password       Plaintext P — zeroed on return.
// @param stored_salt    Salt S from device-local DB.
// @param server_record  RegistrationPayload from server DB.
// @returns              true iff authentication succeeds.
bool AuthenticateUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& stored_salt,
    const RegistrationPayload& server_record);

}  // namespace auth