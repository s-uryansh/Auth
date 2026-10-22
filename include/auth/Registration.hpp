#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace auth {

// Payload stored on the server after Registration.
// Fields:
//   encrypted_secret_e  = HybridEnc(PKs, B⊕R)   [ML-KEM-768 + AES-256-GCM]
//   encrypted_verifier_ed = HybridEnc(PKs, D)    [ML-KEM-768 + AES-256-GCM]
//   server_nonce_r       = R (16 bytes, server-side only)
//
// Wire format of each encrypted field:
//   [ kem_ct (1088 B) | iv (12 B) | gcm_tag (16 B) | aead_ct (N B) ]
struct RegistrationPayload {
  std::string username;

  // HybridEnc(PKs, B⊕R) — ML-KEM-768 encapsulated + AES-256-GCM encrypted
  std::vector<uint8_t> encrypted_secret_e;

  // HybridEnc(PKs, D)   — ML-KEM-768 encapsulated + AES-256-GCM encrypted
  std::vector<uint8_t> encrypted_verifier_ed;

  // R — server-generated 128-bit nonce; stored server-side only.
  // Required by VerifyOnServer to recover B = (B⊕R) ⊕ R.
  std::vector<uint8_t> server_nonce_r;
};

// RegisterUser — Registration with server-supplied nonce R.
// Flow:
//   1. Server generates R, sends to user.
//   2. User: S,B ←$ {0,1}^128
//            E  = HybridEnc(PKs, B⊕R)
//            C  = H(S, P)
//            D  = HMAC_B(C)
//            ED = HybridEnc(PKs, D)
//            Wipe B,C,D; store S in local_db; transmit {U,E,ED}.
//   3. Server stores T_U = {U, R, E, ED}.
//
// @param username   Identity U.
// @param password   Plaintext P — zeroed on return.
// @param server_r   Nonce R from server (must be exactly 16 bytes).
// @param local_db   Device-local salt store, keyed by username.
// @returns          RegistrationPayload {U, E, ED, R}.
auto RegisterUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& server_r,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

// RegisterUser — Registration with caller-supplied protocol salt S and
// server nonce R. Both values must be exactly 16 bytes. This overload is for
// callers that persist S locally alongside an encrypted credential.
auto RegisterUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& server_r,
    const std::vector<uint8_t>& salt_s,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

// RegisterUser — Registration with internally-generated R.
// Generates R via CSPRNG and delegates to the explicit-nonce overload.
// Use in tests and single-process simulations.
//
// @param username   Identity U.
// @param password   Plaintext P — zeroed on return.
// @param local_db   Device-local salt store, keyed by username.
// @returns          RegistrationPayload {U, E, ED, R}.
auto RegisterUser(
    const std::string& username,
    std::vector<uint8_t>& password,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

// RegisterUserWithSalt — Registration with caller-supplied protocol salt S
// and an internally-generated server nonce R. S must be exactly 16 bytes.
// A distinct name avoids a signature collision with the existing overload
// that accepts an explicit server nonce.
auto RegisterUserWithSalt(
    const std::string& username,
    std::vector<uint8_t>& password,
    const std::vector<uint8_t>& salt_s,
    std::unordered_map<std::string, std::vector<uint8_t>>& local_db)
    -> RegistrationPayload;

}  // namespace auth
