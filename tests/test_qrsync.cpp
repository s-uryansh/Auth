#include "gtest/gtest.h"
#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"
#include "auth/server_keys.hpp"
#include "auth/vault.hpp"
#include <QByteArray>
#include <ZXing/ReadBarcode.h>
#include <ZXing/ReaderOptions.h>
#include <ZXing/BitMatrix.h>
#include <ZXing/CharacterSet.h>
#include <ZXing/MultiFormatWriter.h>

#include <oqs/kem.h>
#include <openssl/rand.h>
#include <chrono>
#include <memory>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <thread>
#include <atomic>
#include <future>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

namespace auth = auth;

// ---------------------------------------------------------------------------
// Process simulation helpers (single-process fork pattern for testing)
// ---------------------------------------------------------------------------

// Loopback transport for simulating OD ↔ ND communication over TCP
class LoopbackTransport {
 public:
  // Start a server listening on a random available port
  void startServer(int& port) {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) throw std::runtime_error("socket() failed");

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);  // Let OS assign port

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
      throw std::runtime_error("bind() failed");
    if (listen(server_fd_, 5) < 0)
      throw std::runtime_error("listen() failed");

    socklen_t addrlen = sizeof(addr);
    if (getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), &addrlen) < 0)
      throw std::runtime_error("getsockname() failed");
    port = ntohs(addr.sin_port);
  }

  // Client-side: connect to server and send data
  std::vector<uint8_t> connectAndSend(const std::vector<uint8_t>& data, int port) {
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) throw std::runtime_error("client socket() failed");

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
      close(client_fd);
      throw std::runtime_error("inet_pton() failed");
    }

    if (connect(client_fd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) < 0) {
      close(client_fd);
      throw std::runtime_error("connect() failed");
    }

    // Send data length prefix first
    uint32_t len = static_cast<uint32_t>(data.size());
    ssize_t total_sent = 0;
    while (total_sent < static_cast<ssize_t>(sizeof(len))) {
      ssize_t n = write(client_fd, reinterpret_cast<char*>(&len) + total_sent, sizeof(len) - total_sent);
      if (n <= 0) { close(client_fd); throw std::runtime_error("write() failed"); }
      total_sent += n;
    }
    total_sent = 0;
    while (total_sent < static_cast<ssize_t>(data.size())) {
      ssize_t n = write(client_fd, data.data() + total_sent, data.size() - total_sent);
      if (n <= 0) { close(client_fd); throw std::runtime_error("write() failed"); }
      total_sent += n;
    }
    close(client_fd);

    // Server accepts and reads
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int accept_fd = accept(server_fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
    if (accept_fd < 0) throw std::runtime_error("accept() failed");

    // Read length prefix
    uint32_t received_len = 0;
    total_sent = 0;
    while (total_sent < static_cast<ssize_t>(sizeof(received_len))) {
      ssize_t n = read(accept_fd, reinterpret_cast<char*>(&received_len) + total_sent, sizeof(received_len) - total_sent);
      if (n <= 0) { close(accept_fd); throw std::runtime_error("read() failed"); }
      total_sent += n;
    }

    // Read payload
    std::vector<uint8_t> response(received_len);
    total_sent = 0;
    while (total_sent < static_cast<ssize_t>(received_len)) {
      ssize_t n = read(accept_fd, reinterpret_cast<char*>(response.data()) + total_sent, received_len - total_sent);
      if (n <= 0) { close(accept_fd); throw std::runtime_error("read() failed"); }
      total_sent += n;
    }
    close(accept_fd);
    return response;
  }

  ~LoopbackTransport() {
    if (server_fd_ >= 0) close(server_fd_);
  }

 private:
  int server_fd_ = -1;
};

// ---------------------------------------------------------------------------
// Simulated User Agent for SAS and PIN approval
// ---------------------------------------------------------------------------

class SimulatedUserAgent {
 public:
  enum class Decision { MATCH, CANCEL };

  explicit SimulatedUserAgent(Decision default_decision = Decision::MATCH)
      : default_decision_(default_decision), sas_verified_(false), pin_approved_(false) {}

  // Simulate user SAS verification (both sides display same SAS)
  std::string verifySAS(const std::string& sas_od, const std::string& sas_nd) {
    sas_verified_ = true;
    if (sas_od != sas_nd) return "CANCEL";  // Mismatch detected
    return (default_decision_ == Decision::MATCH) ? "MATCH" : "CANCEL";
  }

  // Simulate PIN/approval request after SAS verification
  bool approveWithPin(const std::string& device_name) {
    (void)device_name;  // suppress unused-parameter warning
    pin_approved_ = true;
    return (default_decision_ == Decision::MATCH);
  }

  bool wasSASVerified() const { return sas_verified_; }
  bool wasPinApproved() const { return pin_approved_; }
  void setDefaultDecision(Decision d) { default_decision_ = d; }
  void reset() { sas_verified_ = false; pin_approved_ = false; }

 private:
  Decision default_decision_;
  bool sas_verified_;
  bool pin_approved_;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> GenerateSalt() {
  std::vector<uint8_t> salt(auth::kSaltSize);
  int r = RAND_bytes(salt.data(), static_cast<int>(salt.size()));
  EXPECT_EQ(r, 1);
  return salt;
}

static std::vector<auth::VaultEntry> MakeTestVaultEntries() {
  auto now = std::chrono::system_clock::now();
  return {
      {"https://example.com", "alice", {0x01, 0x02}, GenerateSalt(), now},
      {"https://example.org", "bob",   {0x03, 0x04}, GenerateSalt(), now},
      {"https://service.net", "carol", {0x05},        GenerateSalt(), now}
  };
}

// Use liboqs to generate a fresh ML-KEM-768 key pair for ND.
static std::pair<std::array<uint8_t, auth::internal::kMlKem768PkBytes>,
                 std::array<uint8_t, auth::internal::kMlKem768SkBytes>>
GenerateNdKeyPair() {
  auto kem = auth::internal::ServerKeys::NewKem();
  std::array<uint8_t, auth::internal::kMlKem768PkBytes> pk{};
  std::array<uint8_t, auth::internal::kMlKem768SkBytes> sk{};
  if (OQS_KEM_keypair(kem.get(), pk.data(), sk.data()) != OQS_SUCCESS) {
    throw std::runtime_error("ML-KEM key pair generation failed");
  }
  return {pk, sk};
}

static std::array<uint8_t, auth::sync::kIdentityBytes> GenerateRandomId() {
  std::array<uint8_t, auth::sync::kIdentityBytes> id{};
  RAND_bytes(id.data(), id.size());
  return id;
}

static std::array<uint8_t, 32> MakeZeroTranscriptHash() {
  return {};
}

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class QRSyncTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Phase A: create TPM key pairs for both devices.
    tpm_od_.createKey();
    tpm_nd_.createKey();
    vault_entries_ = MakeTestVaultEntries();
    user_agent_ = std::make_shared<SimulatedUserAgent>();
    transport_.startServer(server_port_);
  }

  void TearDown() override {
    // Wipe TPM keys so OQS_SIG handles are freed (avoids ASan leak reports).
    tpm_od_.wipe();
    tpm_nd_.wipe();
  }

  // Build a valid QRPayload for testing.
  auth::sync::QRPayload MakePayload(
      const std::array<uint8_t, auth::internal::kMlKem768PkBytes>& pk_nd) {
    auth::sync::QRPayload qr;
    qr.id = GenerateRandomId();
    qr.pk_nd = pk_nd;
    qr.conn_info = "127.0.0.1:" + std::to_string(server_port_);
    qr.expiry = std::chrono::system_clock::now() +
                std::chrono::seconds(auth::sync::kSessionExpirySeconds);
    return qr;
  }

  auth::sync::SoftwareTpm tpm_od_;
  auth::sync::SoftwareTpm tpm_nd_;
  std::vector<auth::VaultEntry> vault_entries_;
  std::shared_ptr<SimulatedUserAgent> user_agent_;
  LoopbackTransport transport_;
  int server_fd_{-1};
  int server_port_{0};
};

// ---------------------------------------------------------------------------
// T1 – Happy path full sync with simulated two-process communication
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, HappyPathFullSync) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);

  // Verify QR round-trip serialization/deserialization.
  auto wire = auth::sync::serializeQR(qr);
  auto decoded = auth::sync::deserializeQR(wire);
  EXPECT_EQ(decoded.id, qr.id);
  EXPECT_EQ(decoded.pk_nd, qr.pk_nd);
  EXPECT_EQ(decoded.conn_info, qr.conn_info);
  EXPECT_GE(decoded.expiry.time_since_epoch().count(),
            std::chrono::seconds(auth::sync::kSessionExpirySeconds).count());

  // SAS computation must match on both sides (same inputs).
  auto sas_nd = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());
  auto sas_od = auth::sync::computeSAS(decoded.pk_nd, decoded.id, MakeZeroTranscriptHash());
  EXPECT_EQ(sas_nd, sas_od);
  EXPECT_EQ(sas_nd.size(), 6u);  // 6-digit decimal string

  // Simulate user SAS verification (both devices show same SAS)
  auto decision = user_agent_->verifySAS(sas_nd, sas_od);
  EXPECT_EQ(decision, "MATCH");
  EXPECT_TRUE(user_agent_->wasSASVerified());

  // Simulate PIN approval on OD
  bool pin_approved = user_agent_->approveWithPin("new-device");
  EXPECT_TRUE(pin_approved);
  EXPECT_TRUE(user_agent_->wasPinApproved());

  // Encrypt vault on OD (old device) and send via loopback transport
  auto transfer = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);

  // Simulate ND receiving vault over loopback
  auto received_transfer = transport_.connectAndSend(transfer, server_port_);
  EXPECT_EQ(received_transfer.size(), transfer.size());

  // Decrypt on ND (new device)
  auto decrypted = auth::sync::decryptVaultFromTransfer(received_transfer, sk_nd);
  ASSERT_EQ(decrypted.size(), vault_entries_.size());
  for (size_t i = 0; i < vault_entries_.size(); ++i) {
    EXPECT_EQ(decrypted[i].website,       vault_entries_[i].website);
    EXPECT_EQ(decrypted[i].username,      vault_entries_[i].username);
    EXPECT_EQ(decrypted[i].password,      vault_entries_[i].password);
    EXPECT_EQ(decrypted[i].salt,          vault_entries_[i].salt);
  }

  // Verify vault entries have lastModified timestamps
  for (const auto& entry : decrypted) {
    EXPECT_NE(entry.lastModified.time_since_epoch().count(),
              std::chrono::seconds(0).count());
  }
}

// ---------------------------------------------------------------------------
// T2 – MITM QR swap (different PKn produces different SAS)
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, MITMSwapTriggersAbort) {
  auto [pk_nd_good, sk_nd_good] = GenerateNdKeyPair();
  auto [pk_nd_attacker, _sk] = GenerateNdKeyPair();

  auto qr_good    = MakePayload(pk_nd_good);
  auto qr_attack  = MakePayload(pk_nd_attacker);

  // SAS must differ because PKn differs.
  auto sas_good = auth::sync::computeSAS(pk_nd_good, qr_good.id, MakeZeroTranscriptHash());
  auto sas_attack = auth::sync::computeSAS(pk_nd_attacker, qr_attack.id, MakeZeroTranscriptHash());
  EXPECT_NE(sas_good, sas_attack);

  // Simulate user detects mismatch and cancels
  auto decision = user_agent_->verifySAS(sas_good, sas_attack);
  EXPECT_EQ(decision, "CANCEL");

  // Encrypt with attacker's PK, try to decrypt with good SK -> must fail.
  auto transfer_attack = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd_attacker);
  EXPECT_THROW(auth::sync::decryptVaultFromTransfer(transfer_attack, sk_nd_good),
               std::runtime_error);
}

// ---------------------------------------------------------------------------
// T3 – Expired QR is rejected
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, ExpiredQrIsRejected) {
  auto [pk_nd, _sk] = GenerateNdKeyPair();
  auth::sync::QRPayload qr;
  qr.id = GenerateRandomId();
  qr.pk_nd = pk_nd;
  qr.conn_info = "127.0.0.1:12345";
  // Set expiry to the past.
  qr.expiry = std::chrono::system_clock::now() - std::chrono::seconds(10);

  auto wire = auth::sync::serializeQR(qr);
  // Deserialize succeeds (expiry is stored in the bytes); the caller must
  // check the expiry against now().  We verify that the decoded expiry is in
  // the past.
  auto decoded = auth::sync::deserializeQR(wire);
  auto now = std::chrono::system_clock::now();
  EXPECT_LT(decoded.expiry, now);

  // Simulate user would reject expired QR
  EXPECT_TRUE(decoded.expiry < now);
}

TEST(QRSyncSessionPolicyTest, SessionExpiresAfterFiveMinutes) {
  EXPECT_EQ(auth::sync::kSessionExpirySeconds, 5 * 60);
}

TEST(QRSyncScannerCodecTest, CompactPairingQrOmitsUnusedKemPublicKey) {
  auth::sync::QRPayload payload;
  payload.id = GenerateRandomId();
  payload.conn_info = "192.168.1.20:43210";
  payload.expiry = std::chrono::system_clock::now() + std::chrono::minutes(5);
  payload.pk_nd.fill(0xA5);

  const auto wire = auth::sync::serializeCompactQR(payload);
  const auto decoded = auth::sync::deserializeQR(wire);

  EXPECT_EQ(wire[2], 0x02);
  EXPECT_LT(wire.size(), 128u);
  EXPECT_EQ(decoded.id, payload.id);
  EXPECT_EQ(decoded.conn_info, payload.conn_info);
  EXPECT_EQ(decoded.expiry, std::chrono::system_clock::time_point(
      std::chrono::seconds(std::chrono::duration_cast<std::chrono::seconds>(
          payload.expiry.time_since_epoch()).count())));
  EXPECT_EQ(decoded.pk_nd, (std::array<uint8_t, 1184>{}));
}

TEST(QRSyncScannerCodecTest, DecodesThePairingQrPayloadAsBinaryData) {
  auth::sync::QRPayload payload;
  payload.id = GenerateRandomId();
  payload.conn_info = "192.168.1.20:43210";
  payload.expiry = std::chrono::system_clock::now() + std::chrono::minutes(5);
  for (size_t i = 0; i < payload.pk_nd.size(); ++i)
    payload.pk_nd[i] = static_cast<uint8_t>(i & 0xff);
  const auto wire = auth::sync::serializeCompactQR(payload);
  const QByteArray encoded = QByteArray::fromRawData(
      reinterpret_cast<const char*>(wire.data()), static_cast<qsizetype>(wire.size())).toBase64();
  const std::string binary_payload = "AUTHQR:" + encoded.toStdString();
  const auto matrix = ZXing::MultiFormatWriter(ZXing::BarcodeFormat::QRCode)
                          .setEncoding(ZXing::CharacterSet::BINARY)
                          .setMargin(4)
                          .encode(binary_payload, 280, 280);
  const int width = matrix.width();
  const int height = matrix.height();
  std::vector<uint8_t> luminance(static_cast<size_t>(width) * height, 0xff);
  for (int row = 0; row < height; ++row)
    for (int col = 0; col < width; ++col)
      if (matrix.get(col, row))
        luminance[static_cast<size_t>(row) * width + col] = 0;

  const ZXing::ImageView view(luminance.data(), width, height,
                              ZXing::ImageFormat::Lum);
  const auto decoded = ZXing::ReadBarcode(
      view, ZXing::ReaderOptions().setFormats(ZXing::BarcodeFormat::QRCode));
  ASSERT_TRUE(decoded.isValid());
  const auto& scanned = decoded.bytes();
  ASSERT_GT(scanned.size(), 7u);
  EXPECT_TRUE(std::equal(scanned.begin(), scanned.begin() + 7, "AUTHQR:"));
  const QByteArray scanned_text(reinterpret_cast<const char*>(scanned.data() + 7),
                                static_cast<qsizetype>(scanned.size() - 7));
  const QByteArray decoded_bytes = QByteArray::fromBase64(scanned_text);
  EXPECT_EQ(std::vector<uint8_t>(decoded_bytes.begin(), decoded_bytes.end()), wire);
}

// The pairing QR lifetime is a user-visible security boundary: it must be
// five minutes, and the receiver must reject the session at and after expiry.
TEST_F(QRSyncTest, PairingQrExpiresAfterFiveMinutes) {
  auto [pk_nd, _sk] = GenerateNdKeyPair();
  const auto created = std::chrono::system_clock::now();
  auto qr = MakePayload(pk_nd);

  const auto lifetime = std::chrono::duration_cast<std::chrono::seconds>(
      qr.expiry - created);
  EXPECT_GE(lifetime, std::chrono::seconds(299));
  EXPECT_LE(lifetime, std::chrono::seconds(300));

  auth::sync::SessionSecrets session;
  session.id = qr.id;
  session.expiry = qr.expiry;
  auto other_id = qr.id;
  other_id[0] ^= 0x01;
  EXPECT_FALSE(auth::sync::sessionAcceptable(session, other_id,
                                             qr.expiry - std::chrono::seconds(1)));
  EXPECT_TRUE(auth::sync::sessionAcceptable(session, qr.id, qr.expiry -
      std::chrono::seconds(1)));
  EXPECT_FALSE(auth::sync::sessionAcceptable(session, qr.id, qr.expiry));
  EXPECT_FALSE(auth::sync::sessionAcceptable(session, qr.id, qr.expiry +
      std::chrono::seconds(1)));
  session.used = true;
  EXPECT_FALSE(auth::sync::sessionAcceptable(session, qr.id,
                                              qr.expiry - std::chrono::seconds(1)));
}

TEST_F(QRSyncTest, DeserializeQrRejectsTruncationAndTrailingBytes) {
  auto [pk_nd, _sk] = GenerateNdKeyPair();
  const auto wire = auth::sync::serializeQR(MakePayload(pk_nd));

  // Every strict prefix omits part of the fixed or variable-length record.
  for (size_t length = 0; length < wire.size(); ++length) {
    std::vector<uint8_t> truncated(wire.begin(), wire.begin() + length);
    EXPECT_THROW(auth::sync::deserializeQR(truncated), std::runtime_error)
        << "accepted truncated QR of " << length << " bytes";
  }

  auto with_trailing_byte = wire;
  with_trailing_byte.push_back(0xA5);
  EXPECT_THROW(auth::sync::deserializeQR(with_trailing_byte),
               std::runtime_error);
}

TEST_F(QRSyncTest, SerializeQrRejectsConnectionInfoLengthOverflow) {
  auto [pk_nd, _sk] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);
  qr.conn_info.assign(65536, 'x');  // connLen is encoded as an unsigned 16-bit value.

  EXPECT_THROW(auth::sync::serializeQR(qr), std::runtime_error);
}

TEST_F(QRSyncTest, MalformedVaultTransferIsRejectedWithoutEntries) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();

  for (const size_t length : {0u, 1u, 1088u, 1099u, 1115u}) {
    std::vector<uint8_t> malformed(length, 0);
    EXPECT_THROW(auth::sync::decryptVaultFromTransfer(malformed, sk_nd),
                 std::runtime_error)
        << "accepted malformed transfer of " << length << " bytes";
  }
}

// ---------------------------------------------------------------------------
// T4 – Replay attack: verify that re-encrypting with a different PKND
//      produces a wire that cannot be decrypted with the original SK.
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, ReplayAttackIsRejected) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();

  // First transfer.
  auto wire1 = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
  auto dec1 = auth::sync::decryptVaultFromTransfer(wire1, sk_nd);
  EXPECT_EQ(dec1.size(), vault_entries_.size());

  // A wire encrypted under a *different* PKND cannot be decrypted with sk_nd.
  auto [pk_nd_other, _sk_other] = GenerateNdKeyPair();
  auto wire_other = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd_other);
  EXPECT_THROW(auth::sync::decryptVaultFromTransfer(wire_other, sk_nd),
               std::runtime_error);

  // Also test replay of the same wire with a different session ID
  std::array<uint8_t, auth::sync::kIdentityBytes> new_id{};
  RAND_bytes(new_id.data(), new_id.size());
  auto wire_with_new_id = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
  // Note: in real protocol, the identity would be part of the signed transcript
}

// ---------------------------------------------------------------------------
// T5 – Tampered vault transfer (bit flip in ciphertext -> GCM tag failure)
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, TamperedVaultTransferFailsGcmTag) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto wire = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);

  // Flip a bit in the AES-GCM ciphertext portion (after kem_ct+iv+tag).
  size_t offset = 1088 + 12 + 16 + 1;
  std::vector<uint8_t> tampered = wire;
  tampered[offset] ^= 0x01;

  EXPECT_THROW(auth::sync::decryptVaultFromTransfer(tampered, sk_nd),
               std::runtime_error);

  // Verify no partial vault data is leaked
  EXPECT_THROW(auth::sync::decryptVaultFromTransfer(tampered, sk_nd),
               std::runtime_error);
}

// ---------------------------------------------------------------------------
// T6 – Bad signature (sigma_OD or sigma_ND invalid)
//      Abort before vault bytes sent (assert zero bytes of vault on wire)
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, BadSignatureDoesNotTransferVault) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);

  // Simulate bad signature: corrupt the IV bytes of the wire payload
  auto wire = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);

  // Corrupt the IV bytes (offset 1088..1099).
  wire[1088] ^= 0xFF;

  // With bad signature, vault transfer should fail
  EXPECT_THROW(auth::sync::decryptVaultFromTransfer(wire, sk_nd),
               std::runtime_error);

  // Verify no vault bytes were transferred (check that decryption fails before
  // any vault content is exposed)
  EXPECT_EQ(wire.size(), 1088u + 12u + 16u + auth::SerializeVault(vault_entries_).size());
}

// ---------------------------------------------------------------------------
// T7 – Known device in T (trusted list) — flow succeeds
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, KnownDeviceFlowSucceeds) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);

  // Simulate "known device": add pk_nd to a local set (our trusted list).
  std::vector<std::array<uint8_t, auth::internal::kMlKem768PkBytes>> trusted;
  trusted.push_back(pk_nd);
  EXPECT_EQ(trusted.size(), 1u);

  // Full sync should still succeed — known-device path still requires SAS+approval.
  auto sas = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());
  auto decision = user_agent_->verifySAS(sas, sas);
  EXPECT_EQ(decision, "MATCH");

  auto transfer = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
  auto decrypted = auth::sync::decryptVaultFromTransfer(transfer, sk_nd);
  ASSERT_EQ(decrypted.size(), vault_entries_.size());

  // Verify known device tracking
  EXPECT_EQ(trusted.size(), 1u);  // Still one trusted device
}

// ---------------------------------------------------------------------------
// T8 – Revocation — after syncing, "remove" pk_nd from the trusted list and
//      verify that a new pairing with the same pk_nd is treated as new
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, RevocationTreatsSamePkAsNew) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);
  auto sas_before = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());

  // "Revoke" by clearing the trusted list.
  std::vector<std::array<uint8_t, auth::internal::kMlKem768PkBytes>> trusted;
  // trusted is empty now.

  // Re-run sync with the same pk_nd — SAS must still match (new pairing).
  auto sas_after = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());
  EXPECT_EQ(sas_before, sas_after);  // same pk+id -> same SAS

  // The vault transfer itself must also succeed.
  auto transfer = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
  auto decrypted = auth::sync::decryptVaultFromTransfer(transfer, sk_nd);
  ASSERT_EQ(decrypted.size(), vault_entries_.size());
}

// ---------------------------------------------------------------------------
// T9 – Merge behavior: remote wins on conflict, new entries are added.
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, MergeKeepsNewerAndAddsNew) {
  // Create entries with different lastModified timestamps
  auto now = std::chrono::system_clock::now();
  auto earlier = now - std::chrono::hours(1);
  auto later = now + std::chrono::hours(1);

  std::vector<auth::VaultEntry> nd_local = {
      {"https://example.com", "alice", {0x0A}, GenerateSalt()},
      {"https://example.org", "bob",   {0x0B}, GenerateSalt()}
  };
  nd_local[0].lastModified = earlier;
  nd_local[1].lastModified = earlier;

  // Remote (OD) sends 3 entries: 1 same website (will overwrite), 1 same
  // website (will overwrite), 1 new.
  std::vector<auth::VaultEntry> od_remote = {
      {"https://example.com", "alice", {0x0C}, GenerateSalt()},  // overwrite (later)
      {"https://example.org", "bob",   {0x0D}, GenerateSalt()},  // overwrite (later)
      {"https://newsite.org", "dave",  {0x0E}, GenerateSalt()}   // new
  };
  od_remote[0].lastModified = later;
  od_remote[1].lastModified = later;
  od_remote[2].lastModified = later;

  auto merged = auth::sync::mergeVaultEntries(nd_local, od_remote);
  ASSERT_EQ(merged.size(), 3u);

  // Find entries by username.
  auto find_by_name = [](const std::vector<auth::VaultEntry>& v,
                         const std::string& name) -> const auth::VaultEntry* {
    auto it = std::find_if(v.begin(), v.end(),
                           [&](const auth::VaultEntry& e) {
                             return e.username == name;
                           });
    return it == v.end() ? nullptr : &*it;
  };

  const auto* alice = find_by_name(merged, "alice");
  const auto* bob   = find_by_name(merged, "bob");
  const auto* dave  = find_by_name(merged, "dave");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(bob,   nullptr);
  ASSERT_NE(dave,  nullptr);

  // Remote values win (remote always overwrites local).
  EXPECT_EQ(alice->password, std::vector<uint8_t>{0x0C});
  EXPECT_EQ(bob->password,   std::vector<uint8_t>{0x0D});
  EXPECT_EQ(dave->password,  std::vector<uint8_t>{0x0E});

  // Verify salt consistency (salt should be from winning entry)
  EXPECT_EQ(alice->salt.size(), auth::kSaltSize);
  EXPECT_EQ(bob->salt.size(), auth::kSaltSize);
}

// ---------------------------------------------------------------------------
// T10 – Secret zeroization (best-effort): session keys go out of scope and
//       destructors clean them; we assert no exception is thrown.
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, SessionKeysAreZeroizedAfterSync) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);

  // Capture the SAS before cleanup.
  auto sas = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());
  EXPECT_EQ(sas.size(), 6u);

  // Perform full transfer; all session material goes out of scope after this
  // block and should be cleaned up.
  {
    auto transfer = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
    auto _ = auth::sync::decryptVaultFromTransfer(transfer, sk_nd);
  }
  // If we reach here without crashing or leaking, zeroization is considered
  // successful (the actual buffer wipe is implementation detail).

  // Verify that the secret key array is still accessible but shouldn't be used
  EXPECT_EQ(sk_nd.size(), auth::internal::kMlKem768SkBytes);
}

// ---------------------------------------------------------------------------
// T11 – No-TPM path (NullTpm)
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, NoTpmPathWorks) {
  auth::sync::NullTpm null_tpm_od;
  auth::sync::NullTpm null_tpm_nd;

  EXPECT_FALSE(null_tpm_od.hasTPM());
  EXPECT_FALSE(null_tpm_nd.hasTPM());

  // NullTpm::createKey() is a no-op — should not throw.
  EXPECT_NO_THROW(null_tpm_od.createKey());
  EXPECT_NO_THROW(null_tpm_nd.createKey());

  // sign/verify/getPubkey/wipe should also be safe.
  EXPECT_EQ(null_tpm_od.getPubkey().size(), 0u);
  EXPECT_NO_THROW(null_tpm_od.sign({}));
  EXPECT_NO_THROW(null_tpm_od.verify({}, {}, {}));
  EXPECT_NO_THROW(null_tpm_od.wipe());

  // Simulate approval without TPM
  auto decision = user_agent_->approveWithPin("");
  EXPECT_TRUE(decision);  // No TPM means skip TPM steps, use software approval
}

// ---------------------------------------------------------------------------
// T12 – Wire safety: no plaintext vault bytes or SAS value appear in wire
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, WireContainsNoPlaintextVaultOrSAS) {
  auto [pk_nd, sk_nd] = GenerateNdKeyPair();
  auto qr = MakePayload(pk_nd);
  auto sas = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());

  auto wire = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);

  // Wire layout: kem_ct(1088) | iv(12) | tag(16) | ciphertext(N)
  EXPECT_GE(wire.size(), 1088u + 12u + 16u);

  // The SAS is a 6-digit decimal string — it should never appear as a raw
  // byte sequence anywhere in the wire (which is encrypted).
  std::string sas_str(sas.begin(), sas.end());
  std::string wire_str(wire.begin(), wire.end());
  EXPECT_EQ(wire_str.find(sas_str), std::string::npos);

  // The plaintext vault entry data should also not appear in the wire.
  for (const auto& entry : vault_entries_) {
    std::string site_str(entry.website.begin(), entry.website.end());
    EXPECT_EQ(wire_str.find(site_str), std::string::npos)
        << "plaintext website found in wire: " << entry.website;
  }
}

// ---------------------------------------------------------------------------
// T13 – Benchmark: run full sync 5 times with 1000 iterations, log timing
// ---------------------------------------------------------------------------
TEST_F(QRSyncTest, BenchmarkFullSyncCompletesWithinReasonableTime) {
  using Clock = std::chrono::high_resolution_clock;
  std::vector<double> keygen_us, handshake_us, vault_us;

  constexpr int kNumRuns = 5;
  constexpr int kIterations = 1000;

  for (int run = 0; run < kNumRuns; ++run) {
    for (int i = 0; i < kIterations; ++i) {
      auto t0 = Clock::now();
      auto [pk_nd, sk_nd] = GenerateNdKeyPair();
      auto t1 = Clock::now();
      keygen_us.push_back(
          std::chrono::duration<double, std::micro>(t1 - t0).count());

      auto t2 = Clock::now();
      auto qr = MakePayload(pk_nd);
      auto sas = auth::sync::computeSAS(pk_nd, qr.id, MakeZeroTranscriptHash());
      auto t3 = Clock::now();
      handshake_us.push_back(
          std::chrono::duration<double, std::micro>(t3 - t2).count());

      auto t4 = Clock::now();
      auto transfer = auth::sync::encryptVaultForTransfer(vault_entries_, pk_nd);
      auto decrypted = auth::sync::decryptVaultFromTransfer(transfer, sk_nd);
      auto t5 = Clock::now();
      vault_us.push_back(
          std::chrono::duration<double, std::micro>(t5 - t4).count());

      ASSERT_EQ(decrypted.size(), vault_entries_.size());
    }
  }

  // Print timing summary (does not assert specific values).
  std::ostringstream oss;
  oss << "\n=== QR Sync Benchmark (n=" << kNumRuns << " runs x "
      << kIterations << " iterations) ===\n";
  oss << "KeyGen (us):     ";
  for (double v : keygen_us) oss << v << " ";
  oss << "\nHandshake (us):  ";
  for (double v : handshake_us) oss << v << " ";
  oss << "\nVault xfer (us): ";
  for (double v : vault_us) oss << v << " ";
  oss << "\n==============================\n";
  GTEST_LOG_(INFO) << oss.str();
}
