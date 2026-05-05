#include <gtest/gtest.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<uint8_t> MakePw(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

// ── Fixture: runs RegisterUser once, reused by all auth tests ─────────────────

class AuthFixture : public ::testing::Test {
 protected:
  const std::string kUsername = "alice";
  const std::string kPassword = "correct_horse_battery_staple";

  std::unordered_map<std::string, std::vector<uint8_t>> user_db;
  auth::RegistrationPayload payload;

  void SetUp() override {
    auto pw = MakePw(kPassword);
    payload  = auth::RegisterUser(kUsername, pw, user_db);
  }
};

// ── Registration ──────────────────────────────────────────────────────────────

TEST_F(AuthFixture, PayloadUsernameCorrect) {
  EXPECT_EQ(payload.username, kUsername);
}

TEST_F(AuthFixture, PayloadEncryptedFieldsNonEmpty) {
  EXPECT_FALSE(payload.encrypted_secret_e.empty());
  EXPECT_FALSE(payload.encrypted_verifier_ed.empty());
}

TEST_F(AuthFixture, SaltStoredLocally_128bit) {
  ASSERT_TRUE(user_db.count(kUsername));
  EXPECT_EQ(user_db.at(kUsername).size(), 16u);
}

TEST_F(AuthFixture, PasswordWipedAfterRegistration) {
  auto pw = MakePw("another_password");
  std::unordered_map<std::string, std::vector<uint8_t>> db;
  auth::RegisterUser("bob", pw, db);
  for (auto b : pw) EXPECT_EQ(b, 0x00);
}

TEST_F(AuthFixture, TwoRegistrationsSaltsDiffer) {
  auto pw1 = MakePw(kPassword);
  auto pw2 = MakePw(kPassword);
  std::unordered_map<std::string, std::vector<uint8_t>> db1, db2;
  auth::RegisterUser("u1", pw1, db1);
  auth::RegisterUser("u2", pw2, db2);
  EXPECT_NE(db1["u1"], db2["u2"]);
}

// ── Authentication ────────────────────────────────────────────────────────────

TEST_F(AuthFixture, CorrectPasswordSucceeds) {
  auto pw = MakePw(kPassword);
  EXPECT_TRUE(
      auth::AuthenticateUser(kUsername, pw, user_db[kUsername], payload));
}

TEST_F(AuthFixture, WrongPasswordFails) {
  auto pw = MakePw("wrong_password");
  EXPECT_FALSE(
      auth::AuthenticateUser(kUsername, pw, user_db[kUsername], payload));
}

TEST_F(AuthFixture, EmptyPasswordFails) {
  std::vector<uint8_t> pw;
  EXPECT_FALSE(
      auth::AuthenticateUser(kUsername, pw, user_db[kUsername], payload));
}

TEST_F(AuthFixture, PasswordWipedAfterAuth) {
  auto pw = MakePw(kPassword);
  auth::AuthenticateUser(kUsername, pw, user_db[kUsername], payload);
  for (auto b : pw) EXPECT_EQ(b, 0x00);
}

TEST_F(AuthFixture, MultipleCorrectAuthsSucceed) {
  for (int i = 0; i < 3; ++i) {
    auto pw = MakePw(kPassword);
    EXPECT_TRUE(
        auth::AuthenticateUser(kUsername, pw, user_db[kUsername], payload));
  }
}

// ── Client / Server boundary ──────────────────────────────────────────────────

TEST_F(AuthFixture, ClientHashDeterministic) {
  auto pw1 = MakePw(kPassword);
  auto pw2 = MakePw(kPassword);
  auto c1  = auth::ComputeClientHash(user_db[kUsername], pw1);
  auto c2  = auth::ComputeClientHash(user_db[kUsername], pw2);
  EXPECT_EQ(c1, c2);
}

TEST_F(AuthFixture, ClientHashDiffersForDiffPasswords) {
  auto pw1 = MakePw("pass_one");
  auto pw2 = MakePw("pass_two");
  auto c1  = auth::ComputeClientHash(user_db[kUsername], pw1);
  auto c2  = auth::ComputeClientHash(user_db[kUsername], pw2);
  EXPECT_NE(c1, c2);
}

TEST_F(AuthFixture, ServerRejectsWrongUsername) {
  auto pw     = MakePw(kPassword);
  auto hash_c = auth::ComputeClientHash(user_db[kUsername], pw);
  EXPECT_FALSE(auth::VerifyOnServer("eve", hash_c, payload));
}

TEST_F(AuthFixture, ServerVerifyCorrectHashSucceeds) {
  auto pw     = MakePw(kPassword);
  auto hash_c = auth::ComputeClientHash(user_db[kUsername], pw);
  EXPECT_TRUE(auth::VerifyOnServer(kUsername, hash_c, payload));
}

TEST_F(AuthFixture, ServerVerifyWrongHashFails) {
  auto pw     = MakePw("wrong");
  auto hash_c = auth::ComputeClientHash(user_db[kUsername], pw);
  EXPECT_FALSE(auth::VerifyOnServer(kUsername, hash_c, payload));
}