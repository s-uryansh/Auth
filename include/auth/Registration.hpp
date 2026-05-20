#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace auth {

// ── RegistrationPayload ───────────────────────────────────────────────────────
//
// Payload stored on the server after Protocol 1 (Registration).
//
// v2 changes from v1:
//   • encrypted_secret_e  = HybridEnc(PKs, B⊕R)   [ML-KEM-768 + AES-256-GCM]
//   • encrypted_verifier_ed = HybridEnc(PKs, D)    [ML-KEM-768 + AES-256-GCM]
//   • server_nonce_r       = R (16 bytes, stays server-side only)
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

// ── RegisterUser (explicit nonce) ─────────────────────────────────────────────
//
// Protocol 1 — Registration with server-supplied nonce R.
//
// Flow:
//   1. Server generates R ←$ {0,1}^128, sends to user.
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

// ── RegisterUser (self-contained) ────────────────────────────────────────────
//
// Protocol 1 — Registration with internally-generated R.
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

}  // namespace auth