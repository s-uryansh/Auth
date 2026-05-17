#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

// ── In-process mocks ────────────────────────────────────────────────────────
// UserDB  : device-local store   — maps username → salt S
// ServerDB: server-side store    — maps username → RegistrationPayload
//           (payload now includes R, E=Enc(PKs,B⊕R), ED=Enc(PKs,D))
std::unordered_map<std::string, std::vector<uint8_t>> UserDB;
std::unordered_map<std::string, auth::RegistrationPayload> ServerDB;

namespace auth {

// Zero-copy password intake: moves bytes out of raw string and wipes it.
std::vector<uint8_t> SecurePasswordInput(std::string& raw) {
  std::vector<uint8_t> v(raw.begin(), raw.end());
  OPENSSL_cleanse(&raw[0], raw.size());
  return v;
}

// Server-side helper: generate the nonce R ←$ {0,1}^128.
// In a real system this would happen on the server before any user data
// arrives; here we simulate it inline.
std::vector<uint8_t> ServerGenerateNonce(size_t bytes = 16) {
  std::vector<uint8_t> r(bytes);
  if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
    throw std::runtime_error("CSPRNG failed generating server nonce R");
  return r;
}

}  // namespace auth

int main() {
  const std::string username = "alice";
  const std::string correct_pass = "correct_horse_battery_staple";
  const std::string wrong_pass = "letmein123";

  // ── Phase 1: Registration (updated Protocol 1) ───────────────────────────
  //
  // Flow:
  //   1. User sends U to server.
  //   2. Server generates R and sends it back.
  //   3. User computes E = Enc(PKs, B⊕R), C, D, ED.
  //   4. User sends {U, E, ED}; server stores T_U = {U, R, E, ED}.
  //   5. User device keeps S.
  try {
    // Step 2: server generates nonce R.
    std::vector<uint8_t> server_r = auth::ServerGenerateNonce();

    // Step 3-4: user-side registration (R is passed in).
    std::string raw = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);

    ServerDB[username] =
        auth::RegisterUser(username, pw, server_r, UserDB);

    std::cout << "[Registration] OK\n";
    std::cout << "  ServerDB stores: {U, R, E=Enc(PKs,B⊕R), ED=Enc(PKs,D)}\n";
    std::cout << "  UserDB   stores: {S}\n\n";
  } catch (const std::exception& e) {
    std::cerr << "[Registration] FAILED: " << e.what() << '\n';
    return 1;
  }

  // ── Phase 2a: Authentication — correct password ──────────────────────────
  //
  // Flow:
  //   User sends {U, C}.
  //   Server: B⊕R ← Dec(SKs,E); B = (B⊕R)⊕R; D ← Dec(SKs,ED);
  //           D' ← HMAC_B(C); authenticate iff D==D'.
  {
    std::string raw = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(username, pw, UserDB[username],
                                     ServerDB[username]);
    std::cout << "[Auth valid]   " << (ok ? "PASS" : "FAIL") << '\n';
  }

  // ── Phase 2b: Authentication — wrong password ────────────────────────────
  {
    std::string raw = wrong_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(username, pw, UserDB[username],
                                     ServerDB[username]);
    std::cout << "[Auth invalid] "
              << (!ok ? "PASS (correctly rejected)"
                      : "FAIL (should have rejected)")
              << '\n';
  }

  return 0;
}