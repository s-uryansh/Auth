#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

// ── In-process mocks ─────────────────────────────────────────────────────────
// UserDB  : device-local — maps username → salt S
// ServerDB: server-side  — maps username → RegistrationPayload
//           payload = {U, R, E=HybridEnc(PKs,B⊕R), ED=HybridEnc(PKs,D)}
std::unordered_map<std::string, std::vector<uint8_t>> UserDB;
std::unordered_map<std::string, auth::RegistrationPayload> ServerDB;

namespace auth {

// Zero-copy password intake: moves bytes out of raw string, then wipes it.
std::vector<uint8_t> SecurePasswordInput(std::string& raw) {
  std::vector<uint8_t> v(raw.begin(), raw.end());
  OPENSSL_cleanse(&raw[0], raw.size());
  return v;
}

// Server-side nonce generation: R ←$ {0,1}^128.
std::vector<uint8_t> ServerGenerateNonce(size_t bytes = 16) {
  std::vector<uint8_t> r(bytes);
  if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
    throw std::runtime_error("CSPRNG failed generating server nonce R");
  return r;
}

}  // namespace auth

int main() {
  const std::string username     = "alice";
  const std::string correct_pass = "correct_horse_battery_staple";
  const std::string wrong_pass   = "letmein123";

  // ── Phase 1: Registration (Protocol 1, v2) ────────────────────────────────
  // Enc = ML-KEM-768 encapsulation + AES-256-GCM (hybrid KEM/DEM)
  try {
    std::vector<uint8_t> server_r = auth::ServerGenerateNonce();
    std::string raw = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);

    ServerDB[username] = auth::RegisterUser(username, pw, server_r, UserDB);

    std::cout << "[Registration] OK\n";
    std::cout << "  Enc = ML-KEM-768 + AES-256-GCM (hybrid, FIPS 203)\n";
    std::cout << "  ServerDB: {U, R, E=HybridEnc(B\xe2\x8a\x95R), "
                 "ED=HybridEnc(D)}\n";
    std::cout << "  UserDB:   {S}\n\n";
  } catch (const std::exception& e) {
    std::cerr << "[Registration] FAILED: " << e.what() << '\n';
    return 1;
  }

  // ── Phase 2a: Authentication — correct password ───────────────────────────
  {
    std::string raw = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(
        username, pw, UserDB[username], ServerDB[username]);
    std::cout << "[Auth valid]   " << (ok ? "PASS" : "FAIL") << '\n';
  }

  // ── Phase 2b: Authentication — wrong password ─────────────────────────────
  {
    std::string raw = wrong_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(
        username, pw, UserDB[username], ServerDB[username]);
    std::cout << "[Auth invalid] "
              << (!ok ? "PASS (correctly rejected)"
                      : "FAIL (should have rejected)")
              << '\n';
  }

  return 0;
}