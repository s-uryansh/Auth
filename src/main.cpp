#include <openssl/crypto.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

// In-process mocks for UserDB (device-local) and ServerDB
std::unordered_map<std::string, std::vector<uint8_t>>      UserDB;
std::unordered_map<std::string, auth::RegistrationPayload> ServerDB;

namespace auth {
std::vector<uint8_t> SecurePasswordInput(std::string& raw) {
  std::vector<uint8_t> v(raw.begin(), raw.end());
  OPENSSL_cleanse(&raw[0], raw.size());
  return v;
}
}  // namespace auth

int main() {
  const std::string username     = "alice";
  const std::string correct_pass = "correct_horse_battery_staple";
  const std::string wrong_pass   = "letmein123";

  // Phase 1: Registration
  try {
    std::string raw         = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    ServerDB[username]      = auth::RegisterUser(username, pw, UserDB);
    std::cout << "[Registration] OK\n";
  } catch (const std::exception& e) {
    std::cerr << "[Registration] FAILED: " << e.what() << '\n';
    return 1;
  }

  // Phase 2: Authentication — correct password
  {
    std::string raw         = correct_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(username, pw, UserDB[username],
                                     ServerDB[username]);
    std::cout << "[Auth valid]   " << (ok ? "PASS" : "FAIL") << '\n';
  }

  // Phase 2: Authentication — wrong password
  {
    std::string raw         = wrong_pass;
    std::vector<uint8_t> pw = auth::SecurePasswordInput(raw);
    bool ok = auth::AuthenticateUser(username, pw, UserDB[username],
                                     ServerDB[username]);
    std::cout << "[Auth invalid] " << (!ok ? "PASS (correctly rejected)" : "FAIL (should have rejected)") << '\n';
  }

  return 0;
}