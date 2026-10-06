#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

std::unordered_map<std::string, std::vector<uint8_t>> UserDB;
std::unordered_map<std::string, auth::RegistrationPayload> ServerDB;

namespace auth {

std::vector<uint8_t> SecurePasswordInput(std::string& raw) {
  std::vector<uint8_t> v(raw.begin(), raw.end());
  OPENSSL_cleanse(&raw[0], raw.size());
  return v;
}

std::vector<uint8_t> ServerGenerateNonce(size_t bytes = 16) {
  std::vector<uint8_t> r(bytes);
  if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
    throw std::runtime_error("CSPRNG failed generating server nonce R");
  return r;
}

std::string ToHex(const std::vector<uint8_t>& data, size_t max_len = 16) {
  std::ostringstream oss;
  size_t limit = std::min(data.size(), max_len);
  for (size_t i = 0; i < limit; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(data[i]);
  }
  if (data.size() > max_len) oss << "...";
  return oss.str();
}

}  // namespace auth

int main() {
  const std::string username     = "alice";
  const std::string correct_pass = "correct_horse_battery_staple";
  const std::string wrong_pass   = "letmein123";

  // Phase 1: Registration
  std::vector<uint8_t> server_r = auth::ServerGenerateNonce();
  std::string raw_pass = correct_pass;
  std::vector<uint8_t> password = auth::SecurePasswordInput(raw_pass);
  ServerDB[username] = auth::RegisterUser(username, password, server_r, UserDB);

  const auto& salt = UserDB[username];
  const auto& payload = ServerDB[username];

  std::cout << "Registration: " << username << "\n";
  std::cout << "  UserDB  S = " << auth::ToHex(salt, 32) << "\n";
  std::cout << "  ServerDB R = " << auth::ToHex(payload.server_nonce_r, 32) << "\n";
  std::cout << "  ServerDB E = HybridEnc(B xor R) [" << payload.encrypted_secret_e.size() << " bytes]\n";
  std::cout << "  ServerDB ED = HybridEnc(D) [" << payload.encrypted_verifier_ed.size() << " bytes]\n\n";

  // Phase 2a: Correct password
  raw_pass = correct_pass;
  password = auth::SecurePasswordInput(raw_pass);
  bool ok = auth::AuthenticateUser(username, password, UserDB[username], ServerDB[username]);
  std::cout << "Auth (correct): " << (ok ? "AUTHENTICATED" : "REJECTED") << "\n";

  // Phase 2b: Wrong password
  raw_pass = wrong_pass;
  password = auth::SecurePasswordInput(raw_pass);
  ok = auth::AuthenticateUser(username, password, UserDB[username], ServerDB[username]);
  std::cout << "Auth (wrong):   " << (ok ? "AUTHENTICATED (ERROR)" : "REJECTED") << "\n";

  return 0;
}