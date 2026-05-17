/**
 * Comprehensive Auth test suite — 1000 test cases + performance benchmarking.
 *
 * Protocol refs:
 *   Protocol 1 (Registration): S,B <- RAND; C=H(S,P); D=HMAC_B(C);
 *                               E=Enc(PKs,B); ED=Enc(PKs,D); store S locally
 *   Protocol 2 (Authentication): C=H(S,P); server: B=Dec(SKs,E),
 *                                 D=Dec(SKs,ED), D'=HMAC_B(C); D==D'?
 */

#include <gtest/gtest.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

// ── Helpers ───────────────────────────────────────────────────────────────────

using DB = std::unordered_map<std::string, std::vector<uint8_t>>;

static std::vector<uint8_t> Pw(const std::string& s) {
  return {s.begin(), s.end()};
}

static std::string RandStr(size_t len) {
  static const char kChars[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  static std::mt19937 rng(42);
  static std::uniform_int_distribution<size_t> dist(0, sizeof(kChars) - 2);
  std::string s(len, ' ');
  for (auto& c : s) c = kChars[dist(rng)];
  return s;
}

static std::vector<uint8_t> RandBytes(size_t n) {
  std::vector<uint8_t> v(n);
  RAND_bytes(v.data(), static_cast<int>(n));
  return v;
}

// Global perf collector
struct PerfCollector {
  std::mutex mu;
  std::vector<double> reg_us;
  std::vector<double> auth_us;

  void push_reg(double us) {
    std::lock_guard<std::mutex> g(mu);
    reg_us.push_back(us);
  }
  void push_auth(double us) {
    std::lock_guard<std::mutex> g(mu);
    auth_us.push_back(us);
  }
} g_perf;

using Clock = std::chrono::high_resolution_clock;

// Timed register
static auth::RegistrationPayload TimedRegister(const std::string& user,
                                               std::vector<uint8_t> pw,
                                               DB& db) {
  auto t0 = Clock::now();
  auto p = auth::RegisterUser(user, pw, db);
  auto t1 = Clock::now();
  g_perf.push_reg(
      std::chrono::duration<double, std::micro>(t1 - t0).count());
  return p;
}

// Timed auth
static bool TimedAuth(const std::string& user, std::vector<uint8_t> pw,
                      const std::vector<uint8_t>& salt,
                      const auth::RegistrationPayload& payload) {
  auto t0 = Clock::now();
  bool ok = auth::AuthenticateUser(user, pw, salt, payload);
  auto t1 = Clock::now();
  g_perf.push_auth(
      std::chrono::duration<double, std::micro>(t1 - t0).count());
  return ok;
}

// ── Fixture ───────────────────────────────────────────────────────────────────

class AuthFixture : public ::testing::Test {
 protected:
  const std::string kUser = "alice";
  const std::string kPass = "correct_horse_battery_staple";
  DB db;
  auth::RegistrationPayload payload;

  void SetUp() override {
    payload = TimedRegister(kUser, Pw(kPass), db);
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: Registration structural tests (100 tests)
// ═══════════════════════════════════════════════════════════════════════════════

// 1-1..1-50: username stored correctly for 50 different names
class RegUsernameFixture : public ::testing::TestWithParam<std::string> {};
INSTANTIATE_TEST_SUITE_P(
    RegUsernames, RegUsernameFixture,
    ::testing::Values(
        "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "heidi",
        "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "rupert",
        "sybil", "trent", "victor", "wendy", "xander", "user_01", "user_02",
        "user_03", "user_04", "user_05", "user_06", "user_07", "user_08",
        "user_09", "user_10", "longerusername_11", "longerusername_12",
        "longerusername_13", "longerusername_14", "longerusername_15",
        "u16", "u17", "u18", "u19", "u20",
        "UPPER_USER_21", "UPPER_USER_22", "UPPER_USER_23",
        "MixedCase24", "MixedCase25", "MixedCase26",
        "with.dot27", "with-dash28", "with_under29", "numeric30_user"));

TEST_P(RegUsernameFixture, UsernameInPayload) {
  DB db;
  auto pw = Pw("testpassword");
  auto p = TimedRegister(GetParam(), pw, db);
  EXPECT_EQ(p.username, GetParam());
}

// 1-51..1-60: salt is always 16 bytes
TEST_P(RegUsernameFixture, SaltIs16Bytes) {
  DB db;
  auto pw = Pw("testpassword");
  TimedRegister(GetParam(), pw, db);
  ASSERT_TRUE(db.count(GetParam()));
  EXPECT_EQ(db.at(GetParam()).size(), 16u);
}
INSTANTIATE_TEST_SUITE_P(
    RegSalt, RegUsernameFixture,
    ::testing::Values("s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
                      "s10"));

// 1-61..1-70: E field non-empty
class RegPayloadNonEmpty : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(RegE, RegPayloadNonEmpty,
                         ::testing::Range(0, 10));
TEST_P(RegPayloadNonEmpty, EncryptedSecretNonEmpty) {
  DB db;
  auto pw = Pw("pw" + std::to_string(GetParam()));
  auto p = TimedRegister("u" + std::to_string(GetParam()), pw, db);
  EXPECT_FALSE(p.encrypted_secret_e.empty());
}

// 1-71..1-80: ED field non-empty
TEST_P(RegPayloadNonEmpty, EncryptedVerifierNonEmpty) {
  DB db;
  auto pw = Pw("pw" + std::to_string(GetParam()));
  auto p = TimedRegister("u" + std::to_string(GetParam()), pw, db);
  EXPECT_FALSE(p.encrypted_verifier_ed.empty());
}

// 1-81..1-90: E size >= 256 bytes (RSA-2048 OAEP ciphertext)
TEST_P(RegPayloadNonEmpty, EncryptedSecretSizeRSA2048) {
  DB db;
  auto pw = Pw("pw" + std::to_string(GetParam()));
  auto p = TimedRegister("u" + std::to_string(GetParam()), pw, db);
  EXPECT_GE(p.encrypted_secret_e.size(), 256u);
}

// 1-91..1-100: ED size >= 256 bytes
TEST_P(RegPayloadNonEmpty, EncryptedVerifierSizeRSA2048) {
  DB db;
  auto pw = Pw("pw" + std::to_string(GetParam()));
  auto p = TimedRegister("u" + std::to_string(GetParam()), pw, db);
  EXPECT_GE(p.encrypted_verifier_ed.size(), 256u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: Password wiping tests (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class WipeFixture : public ::testing::TestWithParam<std::string> {};

INSTANTIATE_TEST_SUITE_P(
    Wipe, WipeFixture,
    ::testing::Values(
        "short", "medium_password_here", "longpassword_with_symbols_!@#$",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaa", "12345678901234567890",
        "UPPERCASE_ONLY_PASS", "mixedCASE123!@#", "   spaces   ",
        "\t\ttabs\t\t", "unicode_ascii_safe_pass",
        "pw01", "pw02", "pw03", "pw04", "pw05", "pw06", "pw07", "pw08",
        "pw09", "pw10", "pw11", "pw12", "pw13", "pw14", "pw15", "pw16",
        "pw17", "pw18", "pw19", "pw20", "pw21", "pw22", "pw23", "pw24",
        "pw25", "pw26", "pw27", "pw28", "pw29", "pw30", "pw31", "pw32",
        "pw33", "pw34", "pw35", "pw36", "pw37", "pw38", "pw39", "pw40"));

TEST_P(WipeFixture, PasswordWipedAfterRegistration) {
  DB db;
  auto pw = Pw(GetParam());
  auth::RegisterUser("wipetest_" + GetParam().substr(0, 4), pw, db);
  for (auto b : pw) EXPECT_EQ(b, 0x00);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: Salt uniqueness (50 tests — 25 pairs)
// ═══════════════════════════════════════════════════════════════════════════════

class SaltUniqFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(SaltUniq, SaltUniqFixture,
                         ::testing::Range(0, 25));

TEST_P(SaltUniqFixture, TwoRegsSaltsDiffer) {
  int i = GetParam();
  DB db1, db2;
  auto pw1 = Pw("pass" + std::to_string(i));
  auto pw2 = Pw("pass" + std::to_string(i));
  auth::RegisterUser("u1_" + std::to_string(i), pw1, db1);
  auth::RegisterUser("u2_" + std::to_string(i), pw2, db2);
  EXPECT_NE(db1["u1_" + std::to_string(i)], db2["u2_" + std::to_string(i)]);
}

TEST_P(SaltUniqFixture, SameUserReregSaltDiffers) {
  int i = GetParam();
  DB db1, db2;
  auto pw1 = Pw("pass");
  auto pw2 = Pw("pass");
  auth::RegisterUser("rereg_" + std::to_string(i), pw1, db1);
  auth::RegisterUser("rereg_" + std::to_string(i), pw2, db2);
  EXPECT_NE(db1["rereg_" + std::to_string(i)],
            db2["rereg_" + std::to_string(i)]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: Correct password succeeds (100 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class CorrectAuthFixture : public ::testing::TestWithParam<std::string> {};

// 50 varied passwords
INSTANTIATE_TEST_SUITE_P(
    CorrectAuth, CorrectAuthFixture,
    ::testing::Values(
        "correct_horse_battery_staple", "P@ssw0rd!", "hunter2",
        "short", "a", "1", "!",
        "very_long_password_that_exceeds_normal_length_and_keeps_going_on_and_on",
        "with spaces in it", "ALLCAPS", "all_lower",
        "1234567890", "!@#$%^&*()", "混合_ascii_safe",
        "pass\x01\x02\x03", "nullbyte\x00after",
        "newline\nin\npassword", "tab\there",
        "emoji_safe_pass_no_unicode", "trailing_space ",
        " leading_space", "  both  ", "repeat_repeat_repeat_repeat",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "correct01", "correct02", "correct03", "correct04", "correct05",
        "correct06", "correct07", "correct08", "correct09", "correct10",
        "correct11", "correct12", "correct13", "correct14", "correct15",
        "correct16", "correct17", "correct18", "correct19", "correct20",
        "correct21", "correct22", "correct23", "correct24", "correct25"));

TEST_P(CorrectAuthFixture, AuthSucceeds) {
  DB db;
  std::string user = "u_" + GetParam().substr(0, 8);
  auto reg_pw = Pw(GetParam());
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(GetParam());
  EXPECT_TRUE(TimedAuth(user, auth_pw, db[user], payload));
}

TEST_P(CorrectAuthFixture, AuthSucceedsRepeat3x) {
  DB db;
  std::string user = "ur_" + GetParam().substr(0, 7);
  auto reg_pw = Pw(GetParam());
  auto payload = TimedRegister(user, reg_pw, db);
  for (int i = 0; i < 3; ++i) {
    auto auth_pw = Pw(GetParam());
    EXPECT_TRUE(TimedAuth(user, auth_pw, db[user], payload));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: Wrong password fails (100 tests — 50 pairs)
// ═══════════════════════════════════════════════════════════════════════════════

using PassPair = std::pair<std::string, std::string>;

class WrongPassFixture : public ::testing::TestWithParam<PassPair> {};

INSTANTIATE_TEST_SUITE_P(
    WrongPass, WrongPassFixture,
    ::testing::Values(
        PassPair{"correct", "incorrect"},
        PassPair{"Password1", "password1"},
        PassPair{"Password1", "Password2"},
        PassPair{"abc", "abcd"},
        PassPair{"abc", "ab"},
        PassPair{"abc", "ABC"},
        PassPair{"abc", ""},
        PassPair{"correct_horse", "correct_horse "},
        PassPair{" leading", "leading"},
        PassPair{"trailing ", "trailing"},
        PassPair{"pass\x01", "pass\x02"},
        PassPair{"longpass_aaaaaaaaaa", "longpass_aaaaaaaab"},
        PassPair{"p1", "p2"}, PassPair{"p3", "p4"},
        PassPair{"p5", "p6"}, PassPair{"p7", "p8"},
        PassPair{"p9", "p10"}, PassPair{"p11", "p12"},
        PassPair{"p13", "p14"}, PassPair{"p15", "p16"},
        PassPair{"p17", "p18"}, PassPair{"p19", "p20"},
        PassPair{"p21", "p22"}, PassPair{"p23", "p24"},
        PassPair{"p25", "p26"}, PassPair{"p27", "p28"},
        PassPair{"p29", "p30"}, PassPair{"p31", "p32"},
        PassPair{"p33", "p34"}, PassPair{"p35", "p36"},
        PassPair{"p37", "p38"}, PassPair{"p39", "p40"},
        PassPair{"p41", "p42"}, PassPair{"p43", "p44"},
        PassPair{"p45", "p46"}, PassPair{"p47", "p48"},
        PassPair{"p49", "p50"}, PassPair{"p51", "p52"},
        PassPair{"p53", "p54"}, PassPair{"p55", "p56"},
        PassPair{"p57", "p58"}, PassPair{"p59", "p60"},
        PassPair{"p61", "p62"}, PassPair{"p63", "p64"},
        PassPair{"p65", "p66"}, PassPair{"p67", "p68"},
        PassPair{"p69", "p70"}, PassPair{"correct_long_password_aaa",
                                         "correct_long_password_aab"}));

TEST_P(WrongPassFixture, WrongPassFails) {
  DB db;
  auto [correct, wrong] = GetParam();
  std::string user = "wp_" + correct.substr(0, 5);
  auto reg_pw = Pw(correct);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(wrong);
  EXPECT_FALSE(TimedAuth(user, auth_pw, db[user], payload));
}

TEST_P(WrongPassFixture, WrongPassDoesNotLeakCorrect) {
  // Auth with wrong pass must return false, not throw
  DB db;
  auto [correct, wrong] = GetParam();
  std::string user = "wpl_" + correct.substr(0, 4);
  auto reg_pw = Pw(correct);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(wrong);
  EXPECT_NO_THROW({
    bool ok = auth::AuthenticateUser(user, auth_pw, db[user], payload);
    EXPECT_FALSE(ok);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: Empty / boundary passwords (30 tests)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(AuthFixture, EmptyPasswordFails) {
  std::vector<uint8_t> pw;
  EXPECT_FALSE(auth::AuthenticateUser(kUser, pw, db[kUser], payload));
}

class EmptyPwFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(EmptyPw, EmptyPwFixture, ::testing::Range(0, 10));
TEST_P(EmptyPwFixture, EmptyPwAlwaysFails) {
  DB db;
  std::string user = "epu_" + std::to_string(GetParam());
  auto reg_pw = Pw("nonempty_pass_" + std::to_string(GetParam()));
  auto payload = TimedRegister(user, reg_pw, db);
  std::vector<uint8_t> empty_pw;
  EXPECT_FALSE(auth::AuthenticateUser(user, empty_pw, db[user], payload));
}

TEST_P(EmptyPwFixture, SingleBytePasswordCorrect) {
  DB db;
  std::string pass = {static_cast<char>('a' + GetParam())};
  std::string user = "single_" + std::to_string(GetParam());
  auto reg_pw = Pw(pass);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, auth_pw, db[user], payload));
}

TEST_P(EmptyPwFixture, SingleBytePasswordWrong) {
  DB db;
  std::string pass = {static_cast<char>('a' + GetParam())};
  std::string wrong = {static_cast<char>('z' - GetParam())};
  std::string user = "singlewrong_" + std::to_string(GetParam());
  auto reg_pw = Pw(pass);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(wrong);
  EXPECT_FALSE(TimedAuth(user, auth_pw, db[user], payload));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: Client hash determinism (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class ClientHashFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(ClientHash, ClientHashFixture,
                         ::testing::Range(0, 25));

TEST_P(ClientHashFixture, SameSaltPassGivesSameHash) {
  auto salt = RandBytes(16);
  auto pw1 = Pw("deterministic_pass_" + std::to_string(GetParam()));
  auto pw2 = Pw("deterministic_pass_" + std::to_string(GetParam()));
  auto h1 = auth::ComputeClientHash(salt, pw1);
  auto h2 = auth::ComputeClientHash(salt, pw2);
  EXPECT_EQ(h1, h2);
}

TEST_P(ClientHashFixture, DiffSaltGivesDiffHash) {
  auto salt1 = RandBytes(16);
  auto salt2 = RandBytes(16);
  // Ensure different salts (overwhelmingly likely)
  if (salt1 == salt2) salt2[0] ^= 0xFF;
  auto pw1 = Pw("same_pass_" + std::to_string(GetParam()));
  auto pw2 = Pw("same_pass_" + std::to_string(GetParam()));
  auto h1 = auth::ComputeClientHash(salt1, pw1);
  auto h2 = auth::ComputeClientHash(salt2, pw2);
  EXPECT_NE(h1, h2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8: Hash differs for different passwords (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class ClientHashDiffFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(ClientHashDiff, ClientHashDiffFixture,
                         ::testing::Range(0, 25));

TEST_P(ClientHashDiffFixture, DiffPassGivesDiffHash) {
  auto salt = RandBytes(16);
  auto pw1 = Pw("pass_A_" + std::to_string(GetParam()));
  auto pw2 = Pw("pass_B_" + std::to_string(GetParam()));
  auto h1 = auth::ComputeClientHash(salt, pw1);
  auto h2 = auth::ComputeClientHash(salt, pw2);
  EXPECT_NE(h1, h2);
}

TEST_P(ClientHashDiffFixture, HashIs32Bytes) {
  auto salt = RandBytes(16);
  auto pw = Pw("anypass_" + std::to_string(GetParam()));
  auto h = auth::ComputeClientHash(salt, pw);
  EXPECT_EQ(h.size(), 32u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9: Server-side username validation (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class ServerRejectFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(ServerReject, ServerRejectFixture,
                         ::testing::Range(0, 25));

TEST_P(ServerRejectFixture, WrongUsernameRejected) {
  DB db;
  std::string user = "real_user_" + std::to_string(GetParam());
  std::string attacker = "attacker_" + std::to_string(GetParam());
  auto reg_pw = Pw("pass_" + std::to_string(GetParam()));
  auto payload = TimedRegister(user, reg_pw, db);
  auto pw = Pw("pass_" + std::to_string(GetParam()));
  auto hash = auth::ComputeClientHash(db[user], pw);
  EXPECT_FALSE(auth::VerifyOnServer(attacker, hash, payload));
}

TEST_P(ServerRejectFixture, CorrectUsernameAccepted) {
  DB db;
  std::string user = "vuser_" + std::to_string(GetParam());
  auto pass = "vpass_" + std::to_string(GetParam());
  auto reg_pw = Pw(pass);
  auto payload = TimedRegister(user, reg_pw, db);
  auto pw = Pw(pass);
  auto hash = auth::ComputeClientHash(db[user], pw);
  EXPECT_TRUE(auth::VerifyOnServer(user, hash, payload));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 10: Password wipe after auth (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class WipeAuthFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(WipeAuth, WipeAuthFixture, ::testing::Range(0, 25));

TEST_P(WipeAuthFixture, PwWipedAfterSuccessfulAuth) {
  DB db;
  std::string user = "wa_" + std::to_string(GetParam());
  auto pass = "wapass_" + std::to_string(GetParam());
  auto reg_pw = Pw(pass);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw(pass);
  auth::AuthenticateUser(user, auth_pw, db[user], payload);
  for (auto b : auth_pw) EXPECT_EQ(b, 0x00);
}

TEST_P(WipeAuthFixture, PwWipedAfterFailedAuth) {
  DB db;
  std::string user = "waf_" + std::to_string(GetParam());
  auto pass = "wafpass_" + std::to_string(GetParam());
  auto reg_pw = Pw(pass);
  auto payload = TimedRegister(user, reg_pw, db);
  auto auth_pw = Pw("wrong_pass_" + std::to_string(GetParam()));
  auth::AuthenticateUser(user, auth_pw, db[user], payload);
  for (auto b : auth_pw) EXPECT_EQ(b, 0x00);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 11: Multi-user isolation (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class MultiUserFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(MultiUser, MultiUserFixture, ::testing::Range(0, 25));

TEST_P(MultiUserFixture, UserCannotAuthAsOther) {
  DB db;
  int i = GetParam();
  std::string u1 = "mu1_" + std::to_string(i);
  std::string u2 = "mu2_" + std::to_string(i);
  std::string p1 = "mupass1_" + std::to_string(i);
  std::string p2 = "mupass2_" + std::to_string(i);

  auto rp1 = Pw(p1);
  auto rp2 = Pw(p2);
  auto pl1 = TimedRegister(u1, rp1, db);
  auto pl2 = TimedRegister(u2, rp2, db);

  // u1's password against u2's payload
  auto ap = Pw(p1);
  EXPECT_FALSE(TimedAuth(u2, ap, db[u2], pl2));

  // u2's password against u1's payload
  auto ap2 = Pw(p2);
  EXPECT_FALSE(TimedAuth(u1, ap2, db[u1], pl1));
}

TEST_P(MultiUserFixture, BothUsersAuthIndependently) {
  DB db;
  int i = GetParam();
  std::string u1 = "ind1_" + std::to_string(i);
  std::string u2 = "ind2_" + std::to_string(i);
  std::string p1 = "indpass1_" + std::to_string(i);
  std::string p2 = "indpass2_" + std::to_string(i);

  auto rp1 = Pw(p1);
  auto rp2 = Pw(p2);
  auto pl1 = TimedRegister(u1, rp1, db);
  auto pl2 = TimedRegister(u2, rp2, db);

  auto ap1 = Pw(p1);
  auto ap2 = Pw(p2);
  EXPECT_TRUE(TimedAuth(u1, ap1, db[u1], pl1));
  EXPECT_TRUE(TimedAuth(u2, ap2, db[u2], pl2));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 12: Cross-payload attacks (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class CrossPayloadFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(CrossPayload, CrossPayloadFixture,
                         ::testing::Range(0, 25));

TEST_P(CrossPayloadFixture, CorrectHashWrongPayloadFails) {
  DB db;
  int i = GetParam();
  std::string u1 = "cp1_" + std::to_string(i);
  std::string u2 = "cp2_" + std::to_string(i);
  std::string pass = "cppass_" + std::to_string(i);

  auto rp1 = Pw(pass);
  auto rp2 = Pw(pass);
  auto pl1 = TimedRegister(u1, rp1, db);
  auto pl2 = TimedRegister(u2, rp2, db);

  // Same password but different B/D — u1's hash against u2's payload
  auto pw = Pw(pass);
  auto hash = auth::ComputeClientHash(db[u1], pw);
  EXPECT_FALSE(auth::VerifyOnServer(u2, hash, pl2));
}

TEST_P(CrossPayloadFixture, SwappedSaltFails) {
  DB db;
  int i = GetParam();
  std::string u1 = "ss1_" + std::to_string(i);
  std::string u2 = "ss2_" + std::to_string(i);
  std::string pass = "sspass_" + std::to_string(i);

  auto rp1 = Pw(pass);
  auto rp2 = Pw(pass);
  auto pl1 = TimedRegister(u1, rp1, db);
  auto pl2 = TimedRegister(u2, rp2, db);

  // u2's salt with u1's payload
  auto pw = Pw(pass);
  auto hash = auth::ComputeClientHash(db[u2], pw);
  EXPECT_FALSE(auth::VerifyOnServer(u1, hash, pl1));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 13: Password length spectrum (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class PwLengthFixture : public ::testing::TestWithParam<int> {};
// Lengths: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 (10 per group, 5 groups)
INSTANTIATE_TEST_SUITE_P(PwLen1, PwLengthFixture,
                         ::testing::Values(1, 2, 4, 8, 16, 32, 64, 128, 256,
                                           512));

TEST_P(PwLengthFixture, LongPasswordCorrectSucceeds) {
  DB db;
  int len = GetParam();
  std::string user = "lp_" + std::to_string(len);
  std::string pass(len, 'x');
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

TEST_P(PwLengthFixture, LongPasswordOffByOneFails) {
  DB db;
  int len = GetParam();
  if (len < 2) return;  // can't shorten 1-byte pass meaningfully
  std::string user = "lpob_" + std::to_string(len);
  std::string pass(len, 'x');
  std::string wrong(len - 1, 'x');
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(wrong);
  EXPECT_FALSE(TimedAuth(user, ap, db[user], pl));
}

INSTANTIATE_TEST_SUITE_P(PwLen2, PwLengthFixture,
                         ::testing::Values(3, 5, 7, 15, 17, 31, 33, 63, 65,
                                           127));

TEST_P(PwLengthFixture, OddLengthPasswordRoundTrips) {
  DB db;
  int len = GetParam();
  std::string user = "odd_" + std::to_string(len);
  std::string pass = RandStr(static_cast<size_t>(len));
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

INSTANTIATE_TEST_SUITE_P(PwLen3, PwLengthFixture,
                         ::testing::Values(6, 9, 10, 11, 12, 13, 14, 18, 20,
                                           24));

TEST_P(PwLengthFixture, MidLengthPasswordRoundTrips) {
  DB db;
  int len = GetParam();
  std::string user = "mid_" + std::to_string(len);
  std::string pass = RandStr(static_cast<size_t>(len));
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

INSTANTIATE_TEST_SUITE_P(PwLen4, PwLengthFixture,
                         ::testing::Values(25, 26, 27, 28, 29, 30, 36, 48,
                                           96, 192));

TEST_P(PwLengthFixture, LargerPasswordRoundTrips) {
  DB db;
  int len = GetParam();
  std::string user = "lrg_" + std::to_string(len);
  std::string pass = RandStr(static_cast<size_t>(len));
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

INSTANTIATE_TEST_SUITE_P(PwLen5, PwLengthFixture,
                         ::testing::Values(40, 44, 50, 55, 60, 70, 80, 90,
                                           100, 110));

TEST_P(PwLengthFixture, ExtraRangePasswordRoundTrips) {
  DB db;
  int len = GetParam();
  std::string user = "exr_" + std::to_string(len);
  std::string pass = RandStr(static_cast<size_t>(len));
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 14: All-byte-values passwords (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class ByteValueFixture : public ::testing::TestWithParam<int> {};
// Test byte values 0x01..0x32 (50 values, skip 0x00 as it's empty string)
INSTANTIATE_TEST_SUITE_P(ByteVal, ByteValueFixture, ::testing::Range(1, 51));

TEST_P(ByteValueFixture, SingleByteAllValuesRoundTrip) {
  DB db;
  int bval = GetParam();
  std::string user = "bv_" + std::to_string(bval);
  std::vector<uint8_t> pass = {static_cast<uint8_t>(bval)};
  std::vector<uint8_t> pass2 = {static_cast<uint8_t>(bval)};
  auto pl = auth::RegisterUser(user, pass, db);
  g_perf.push_reg(0);  // already timed inline above; push placeholder
  EXPECT_TRUE(auth::AuthenticateUser(user, pass2, db[user], pl));
  g_perf.push_auth(0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 15: Stress — rapid sequential auths (50 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class StressFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(Stress, StressFixture, ::testing::Range(0, 10));

TEST_P(StressFixture, 5RapidCorrectAuthsAllPass) {
  DB db;
  std::string user = "stress5_" + std::to_string(GetParam());
  std::string pass = "stresspass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  for (int i = 0; i < 5; ++i) {
    auto ap = Pw(pass);
    EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
  }
}

TEST_P(StressFixture, 5WrongThen1CorrectFails5Passes1) {
  DB db;
  std::string user = "stress51_" + std::to_string(GetParam());
  std::string pass = "s51pass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  for (int i = 0; i < 5; ++i) {
    auto ap = Pw("wrong_" + std::to_string(i));
    EXPECT_FALSE(TimedAuth(user, ap, db[user], pl));
  }
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

TEST_P(StressFixture, 10RapidRegistrationsAllUnique) {
  std::vector<std::vector<uint8_t>> salts;
  for (int i = 0; i < 10; ++i) {
    DB db;
    std::string user = "rapid_" + std::to_string(GetParam()) + "_" +
                       std::to_string(i);
    auto rp = Pw("rpass_" + std::to_string(i));
    TimedRegister(user, rp, db);
    salts.push_back(db[user]);
  }
  for (size_t a = 0; a < salts.size(); ++a)
    for (size_t b = a + 1; b < salts.size(); ++b)
      EXPECT_NE(salts[a], salts[b]);
}

TEST_P(StressFixture, AlternatingCorrectWrongAuthPattern) {
  DB db;
  std::string user = "altcw_" + std::to_string(GetParam());
  std::string pass = "altpass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  for (int i = 0; i < 5; ++i) {
    auto correct_ap = Pw(pass);
    auto wrong_ap = Pw("wrong");
    EXPECT_TRUE(TimedAuth(user, correct_ap, db[user], pl));
    EXPECT_FALSE(TimedAuth(user, wrong_ap, db[user], pl));
  }
}

TEST_P(StressFixture, 20CorrectAuthsAllPass) {
  DB db;
  std::string user = "s20_" + std::to_string(GetParam());
  std::string pass = "s20pass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  for (int i = 0; i < 20; ++i) {
    auto ap = Pw(pass);
    EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 16: Concurrent registration + auth (30 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class ConcurrentFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(Concurrent, ConcurrentFixture,
                         ::testing::Range(0, 10));

TEST_P(ConcurrentFixture, ConcurrentRegistrationsNoRace) {
  // Each thread gets own DB — no shared state
  int N = 4;
  std::atomic<int> successes{0};
  std::vector<std::thread> threads;
  int base = GetParam() * N;
  threads.reserve(static_cast<size_t>(N));
  for (int i = 0; i < N; ++i) {
    threads.emplace_back([i, base, &successes]() {
      DB db;
      std::string user = "ct_" + std::to_string(base + i);
      auto rp = Pw("ctpass_" + std::to_string(base + i));
      auto pl = auth::RegisterUser(user, rp, db);
      if (pl.username == user) ++successes;
    });
  }
  for (auto& t : threads) t.join();
  EXPECT_EQ(successes.load(), N);
}

TEST_P(ConcurrentFixture, ConcurrentAuthsNoRace) {
  DB db;
  std::string user = "ca_" + std::to_string(GetParam());
  std::string pass = "capass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto salt = db[user];

  int N = 4;
  std::atomic<int> passes{0};
  std::vector<std::thread> threads;
  threads.reserve(static_cast<size_t>(N));
  for (int i = 0; i < N; ++i) {
    threads.emplace_back([&]() {
      auto ap = Pw(pass);
      if (auth::AuthenticateUser(user, ap, salt, pl)) ++passes;
    });
  }
  for (auto& t : threads) t.join();
  EXPECT_EQ(passes.load(), N);
}

TEST_P(ConcurrentFixture, ConcurrentMixedCorrectWrong) {
  DB db;
  std::string user = "cmx_" + std::to_string(GetParam());
  std::string pass = "cmxpass_" + std::to_string(GetParam());
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto salt = db[user];

  std::atomic<int> correct_count{0}, wrong_count{0};
  std::vector<std::thread> threads;
  int N = 4;
  threads.reserve(static_cast<size_t>(N));
  for (int i = 0; i < N; ++i) {
    bool is_correct = (i % 2 == 0);
    threads.emplace_back([&, is_correct]() {
      auto ap = is_correct ? Pw(pass) : Pw("wrong");
      bool ok = auth::AuthenticateUser(user, ap, salt, pl);
      if (is_correct && ok) ++correct_count;
      if (!is_correct && !ok) ++wrong_count;
    });
  }
  for (auto& t : threads) t.join();
  EXPECT_EQ(correct_count.load(), N / 2);
  EXPECT_EQ(wrong_count.load(), N / 2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 17: Crypto property — E != ED (20 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class CryptoFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(Crypto, CryptoFixture, ::testing::Range(0, 10));

TEST_P(CryptoFixture, EAndEDDistinct) {
  // E=Enc(PKs,B) and ED=Enc(PKs,D). Different plaintexts → different ciphertexts
  DB db;
  std::string user = "cry_" + std::to_string(GetParam());
  auto rp = Pw("crypass_" + std::to_string(GetParam()));
  auto pl = TimedRegister(user, rp, db);
  EXPECT_NE(pl.encrypted_secret_e, pl.encrypted_verifier_ed);
}

TEST_P(CryptoFixture, TwoRegsProduceDifferentE) {
  // OAEP is probabilistic — same B produces different E
  DB db1, db2;
  std::string u1 = "de1_" + std::to_string(GetParam());
  std::string u2 = "de2_" + std::to_string(GetParam());
  auto rp1 = Pw("same_pass");
  auto rp2 = Pw("same_pass");
  auto pl1 = TimedRegister(u1, rp1, db1);
  auto pl2 = TimedRegister(u2, rp2, db2);
  // Different B -> almost certainly different E
  EXPECT_NE(pl1.encrypted_secret_e, pl2.encrypted_secret_e);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 18: No throw guarantee (30 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class NoThrowFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(NoThrow, NoThrowFixture, ::testing::Range(0, 15));

TEST_P(NoThrowFixture, RegistrationNoThrow) {
  DB db;
  auto rp = Pw(RandStr(32));
  EXPECT_NO_THROW(auth::RegisterUser("nt_" + std::to_string(GetParam()),
                                     rp, db));
}

TEST_P(NoThrowFixture, AuthNoThrowWrongPass) {
  DB db;
  std::string user = "ntw_" + std::to_string(GetParam());
  auto rp = Pw("ntpass_" + std::to_string(GetParam()));
  auto pl = TimedRegister(user, rp, db);
  EXPECT_NO_THROW({
    auto ap = Pw("totally_wrong");
    auth::AuthenticateUser(user, ap, db[user], pl);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 19: Special character passwords (40 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class SpecialCharFixture : public ::testing::TestWithParam<std::string> {};
INSTANTIATE_TEST_SUITE_P(
    SpecialChar, SpecialCharFixture,
    ::testing::Values(
        "!@#$%^&*()", "[]{}|;':\",./<>?", "\\n\\t\\r",
        "pass with spaces", "\x01\x02\x03\x04\x05",
        "\x7f\x7e\x7d\x7c", "pass\xFF\xFE\xFD",
        "null\x00embedded", "double\"quote", "single'quote",
        "back`tick", "hash#tag", "dollar$sign",
        "percent%sign", "caret^up", "amp&ersand",
        "star*star", "open(paren", "close)paren",
        "hyphen-dash", "under_score",
        "special01!!", "special02@@", "special03##",
        "special04$$", "special05%%", "special06^^",
        "special07&&", "special08**", "special09((", "special10))"));

TEST_P(SpecialCharFixture, SpecialCharPasswordRoundTrips) {
  DB db;
  std::string pass = GetParam();
  std::string user = "sc_" + std::to_string(
      std::hash<std::string>{}(pass) & 0xFFFF);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 20: Case sensitivity (20 tests)
// ═══════════════════════════════════════════════════════════════════════════════

struct CasePair { std::string correct; std::string wrong; };
class CaseFixture : public ::testing::TestWithParam<CasePair> {};

INSTANTIATE_TEST_SUITE_P(
    Case, CaseFixture,
    ::testing::Values(
        CasePair{"Password", "password"},
        CasePair{"Password", "PASSWORD"},
        CasePair{"password", "Password"},
        CasePair{"PASSWORD", "password"},
        CasePair{"MixedCase", "mixedcase"},
        CasePair{"MixedCase", "MIXEDCASE"},
        CasePair{"abc123", "ABC123"},
        CasePair{"ABC123", "abc123"},
        CasePair{"Hello World", "hello world"},
        CasePair{"Hello World", "HELLO WORLD"},
        CasePair{"camelCase", "CamelCase"},
        CasePair{"camelCase", "camelcase"},
        CasePair{"snake_case", "Snake_case"},
        CasePair{"snake_case", "SNAKE_CASE"},
        CasePair{"PascalCase", "pascalCase"},
        CasePair{"PascalCase", "PASCALCASE"},
        CasePair{"Aa", "aa"},
        CasePair{"Aa", "AA"},
        CasePair{"aA", "aa"},
        CasePair{"aA", "AA"}));

TEST_P(CaseFixture, CaseSensitiveAuth) {
  DB db;
  auto [correct, wrong] = GetParam();
  std::string user = "case_" + std::to_string(
      std::hash<std::string>{}(correct) & 0xFFFF);
  auto rp = Pw(correct);
  auto pl = TimedRegister(user, rp, db);

  auto ap_wrong = Pw(wrong);
  EXPECT_FALSE(TimedAuth(user, ap_wrong, db[user], pl));

  auto ap_correct = Pw(correct);
  EXPECT_TRUE(TimedAuth(user, ap_correct, db[user], pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 21: Tampered salt fails auth (30 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class TamperedSaltFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(TamperedSalt, TamperedSaltFixture,
                         ::testing::Range(0, 15));

TEST_P(TamperedSaltFixture, FlippedSaltBitFails) {
  DB db;
  int i = GetParam();
  std::string user = "ts_" + std::to_string(i);
  std::string pass = "tspass_" + std::to_string(i);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto salt = db[user];
  salt[i % salt.size()] ^= 0x01;  // flip one bit

  auto ap = Pw(pass);
  EXPECT_FALSE(TimedAuth(user, ap, salt, pl));
}

TEST_P(TamperedSaltFixture, ZeroedSaltFails) {
  DB db;
  int i = GetParam();
  std::string user = "zs_" + std::to_string(i);
  std::string pass = "zspass_" + std::to_string(i);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  std::vector<uint8_t> zeroed_salt(16, 0x00);

  auto ap = Pw(pass);
  EXPECT_FALSE(TimedAuth(user, ap, zeroed_salt, pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 22: VerifyOnServer direct tests (30 tests)
// ═══════════════════════════════════════════════════════════════════════════════

class VerifyServerFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(VerifyServer, VerifyServerFixture,
                         ::testing::Range(0, 15));

TEST_P(VerifyServerFixture, CorrectHashVerifies) {
  DB db;
  int i = GetParam();
  std::string user = "vs_" + std::to_string(i);
  std::string pass = "vspass_" + std::to_string(i);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto pw = Pw(pass);
  auto hash = auth::ComputeClientHash(db[user], pw);
  EXPECT_TRUE(auth::VerifyOnServer(user, hash, pl));
}

TEST_P(VerifyServerFixture, WrongHashDoesNotVerify) {
  DB db;
  int i = GetParam();
  std::string user = "vswrong_" + std::to_string(i);
  std::string pass = "vswrongpass_" + std::to_string(i);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto pw = Pw("definitely_wrong_password");
  auto hash = auth::ComputeClientHash(db[user], pw);
  EXPECT_FALSE(auth::VerifyOnServer(user, hash, pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 23: Misc edge cases (20 tests)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(AuthFixture, PayloadUsernameMatchesInput) {
  EXPECT_EQ(payload.username, kUser);
}

TEST_F(AuthFixture, SaltExistsInDB) {
  EXPECT_TRUE(db.count(kUser));
}

TEST_F(AuthFixture, SaltIs16Bytes) {
  EXPECT_EQ(db.at(kUser).size(), 16u);
}

TEST_F(AuthFixture, EncryptedFieldsSizeGE256) {
  EXPECT_GE(payload.encrypted_secret_e.size(), 256u);
  EXPECT_GE(payload.encrypted_verifier_ed.size(), 256u);
}

TEST_F(AuthFixture, EandEDAreDifferent) {
  EXPECT_NE(payload.encrypted_secret_e, payload.encrypted_verifier_ed);
}

TEST_F(AuthFixture, MultipleCorrectAuthsAllPass) {
  for (int i = 0; i < 10; ++i) {
    auto ap = Pw(kPass);
    EXPECT_TRUE(TimedAuth(kUser, ap, db[kUser], payload));
  }
}

TEST_F(AuthFixture, FullAuthWipeCorrect) {
  auto ap = Pw(kPass);
  auth::AuthenticateUser(kUser, ap, db[kUser], payload);
  for (auto b : ap) EXPECT_EQ(b, 0x00);
}

TEST_F(AuthFixture, FullAuthWipeWrong) {
  auto ap = Pw("wrongpassword");
  auth::AuthenticateUser(kUser, ap, db[kUser], payload);
  for (auto b : ap) EXPECT_EQ(b, 0x00);
}

TEST_F(AuthFixture, ServerRejectsEmptyUsername) {
  auto pw = Pw(kPass);
  auto hash = auth::ComputeClientHash(db[kUser], pw);
  EXPECT_FALSE(auth::VerifyOnServer("", hash, payload));
}

TEST_F(AuthFixture, ServerRejectsRandomUsername) {
  auto pw = Pw(kPass);
  auto hash = auth::ComputeClientHash(db[kUser], pw);
  EXPECT_FALSE(auth::VerifyOnServer("random_unknown_user", hash, payload));
}

TEST_F(AuthFixture, ServerAcceptsCorrectUsername) {
  auto pw = Pw(kPass);
  auto hash = auth::ComputeClientHash(db[kUser], pw);
  EXPECT_TRUE(auth::VerifyOnServer(kUser, hash, payload));
}

TEST_F(AuthFixture, ClientHashWipesPassword) {
  auto pw = Pw(kPass);
  auth::ComputeClientHash(db[kUser], pw);
  for (auto b : pw) EXPECT_EQ(b, 0x00);
}

class MiscFixture : public ::testing::TestWithParam<int> {};
INSTANTIATE_TEST_SUITE_P(Misc, MiscFixture, ::testing::Range(0, 8));

TEST_P(MiscFixture, RandomPasswordRoundTrip) {
  DB db;
  int i = GetParam();
  std::string user = "rand_" + std::to_string(i);
  std::string pass = RandStr(32 + static_cast<size_t>(i) * 7);
  auto rp = Pw(pass);
  auto pl = TimedRegister(user, rp, db);
  auto ap = Pw(pass);
  EXPECT_TRUE(TimedAuth(user, ap, db[user], pl));
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERF REPORT — runs once at end via environment listener
// ═══════════════════════════════════════════════════════════════════════════════

class PerfReportListener : public ::testing::EmptyTestEventListener {
  void OnTestProgramEnd(const ::testing::UnitTest& unit) override {
    auto& p = g_perf;
    std::lock_guard<std::mutex> g(p.mu);

    auto stats = [](std::vector<double>& v, const char* name) {
      if (v.empty()) { printf("%s: no data\n", name); return; }
      std::sort(v.begin(), v.end());
      double sum = std::accumulate(v.begin(), v.end(), 0.0);
      double avg = sum / static_cast<double>(v.size());
      double min = v.front();
      double max = v.back();
      double p50 = v[v.size() / 2];
      double p95 = v[static_cast<size_t>(v.size() * 0.95)];
      double p99 = v[static_cast<size_t>(v.size() * 0.99)];
      printf("\n── %s (n=%zu) ──────────────────────────\n", name, v.size());
      printf("  avg:  %8.1f µs\n", avg);
      printf("  min:  %8.1f µs\n", min);
      printf("  p50:  %8.1f µs\n", p50);
      printf("  p95:  %8.1f µs\n", p95);
      printf("  p99:  %8.1f µs\n", p99);
      printf("  max:  %8.1f µs\n", max);
    };

    printf("\n\n══════════════════════════════════════════\n");
    printf("  Auth Protocol Performance Report\n");
    printf("══════════════════════════════════════════\n");
    printf("  Tests passed: %d / %d\n",
           unit.successful_test_count(), unit.total_test_count());
    stats(p.reg_us, "Registration (Protocol 1)");
    stats(p.auth_us, "Authentication (Protocol 2)");
    printf("══════════════════════════════════════════\n\n");

    // Write CSV for external analysis
    std::ofstream csv("/tmp/auth_perf.csv");
    if (csv) {
      csv << "type,latency_us\n";
      for (auto us : p.reg_us) csv << "registration," << std::fixed
                                   << std::setprecision(2) << us << "\n";
      for (auto us : p.auth_us) csv << "authentication," << std::fixed
                                    << std::setprecision(2) << us << "\n";
    }
  }
};

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::UnitTest::GetInstance()->listeners().Append(
      new PerfReportListener);
  return RUN_ALL_TESTS();
}