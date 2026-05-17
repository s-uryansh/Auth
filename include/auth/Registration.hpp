#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace auth {

// Payload transmitted from user device to server after registration.
// Updated Protocol 1: server also stores R (the nonce it generated),
// which is needed during authentication to recover B from B⊕R.
struct RegistrationPayload {
  std::string username;

  // E = Enc(PKs, B⊕R)  — ciphertext of the XOR-masked secret
  std::vector<uint8_t> encrypted_secret_e;

  // ED = Enc(PKs, D)   — ciphertext of the HMAC verifier
  std::vector<uint8_t> encrypted_verifier_ed;

  // R — server-generated nonce stored alongside ciphertext.
  // The server is the only party that ever sees R in plaintext;
  // it is never sent back to the user.
  std::vector<uint8_t> server_nonce_r;
};

// Protocol 1 — Registration (4-arg form, explicit server nonce).
//
// Flow:
//   1. User sends U to server.
//   2. Server replies with R ←$ {0,1}^n  (handled externally; R is passed in).
//   3. User computes:
//        E  ← Enc(PKs, B⊕R)
//        C  ← H(S, P)
//        D  ← HMAC_B(C)
//        ED ← Enc(PKs, D)
//   4. User sends {U, E, ED} to server; deletes B, C, D, E, ED locally.
//   5. Server stores T_U = {U, R, E, ED}.
//   6. User device keeps S in local_db.
//
// @param username   Identity string U.
// @param password   Plaintext password bytes P (wiped on return).
// @param server_r   Nonce R supplied by the server (exactly 16 bytes).
// @param local_db   Device-local salt store; keyed by username.
// @returns          RegistrationPayload containing {U, E, ED, R}.
auto RegisterUser(
    const std::string& username, std::vector<uint8_t>& password,
    const std::vector<uint8_t>& server_r,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

// Protocol 1 — Registration (3-arg convenience overload).
//
// Identical to the 4-arg form except R is generated internally via CSPRNG.
// Use in tests and single-process simulations where the caller does not
// need to observe or supply R directly.
//
// @param username   Identity string U.
// @param password   Plaintext password bytes P (wiped on return).
// @param local_db   Device-local salt store; keyed by username.
// @returns          RegistrationPayload containing {U, E, ED, R}.
auto RegisterUser(
    const std::string& username, std::vector<uint8_t>& password,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

}  // namespace auth