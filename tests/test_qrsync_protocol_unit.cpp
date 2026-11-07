#include "gtest/gtest.h"

#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"

#include <openssl/rand.h>

#include <chrono>
#include <vector>

namespace {

using Clock = std::chrono::system_clock;
constexpr auto kLifetime = std::chrono::seconds(120);

std::vector<auth::VaultEntry> sampleVault() {
  auth::VaultEntry entry;
  entry.website = "https://example.test";
  entry.username = "alice";
  entry.password = {0x01, 0x02, 0x03};
  entry.salt.assign(auth::kSaltSize, 0xA5);
  entry.lastModified = Clock::time_point(std::chrono::seconds(1234));
  return {entry};
}

auth::sync::OdApproval makeApproval(const auth::sync::SessionSecrets& session,
                                    auth::sync::SoftwareTpm& signer) {
  auth::sync::OdApproval approval;
  approval.id = session.id;
  approval.expiry = session.expiry;
  approval.pk_nd = session.pk_nd;
  approval.device_public_key = signer.getPubkey();
  approval.signature = signer.sign(auth::sync::oldDeviceApprovalDigest(
      approval.id, approval.expiry, approval.pk_nd));
  return approval;
}

auth::sync::NdApproval makeNdApproval(const std::string& sas,
                                      const auth::sync::SessionSecrets& session,
                                      auth::sync::SoftwareTpm& signer) {
  auth::sync::NdApproval approval;
  approval.device_public_key = signer.getPubkey();
  approval.signature =
      signer.sign(auth::sync::newDeviceApprovalDigest(sas, session.pk_nd, session.id));
  return approval;
}

auto verifyWith(auth::sync::TpmInterface& signer) {
  return [&signer](const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature,
                   const std::vector<uint8_t>& public_key) {
    return signer.verify(message, signature, public_key);
  };
}

// --- SAS is exactly H(PKn || ID): two inputs, no transcript slot ---

TEST(SasBinding, SameKeyAndSessionIdProduceTheSameCodeOnBothPeers) {
  const auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", Clock::now(), kLifetime);
  const auto recomputed = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  EXPECT_EQ(recomputed, auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id));
  EXPECT_EQ(recomputed.size(), 32U);
}

TEST(SasBinding, ASubstitutedQrKeyChangesTheDisplayedCode) {
  const auto real =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", Clock::now(), kLifetime);
  const auto attacker =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", Clock::now(), kLifetime);
  EXPECT_NE(auth::sync::computeSAS(real.secrets.pk_nd, real.secrets.id),
            auth::sync::computeSAS(attacker.secrets.pk_nd, real.secrets.id));
}

TEST(SasBinding, ADifferentSessionIdChangesTheDisplayedCode) {
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", Clock::now(), kLifetime);
  auto other_id = session.secrets.id;
  other_id.front() ^= 0x01;
  EXPECT_NE(auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id),
            auth::sync::computeSAS(session.secrets.pk_nd, other_id));
}

// --- OD verifies sigma_ND; the vault may not move until it does ---

TEST(NewDeviceApproval, VerifiesASignatureOverSasPkAndSessionId) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);

  const auto authorization = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, makeNdApproval(sas, session.secrets, nd_signer), verifyWith(nd_signer));

  EXPECT_TRUE(authorization.valid());
  EXPECT_EQ(authorization.sessionId(), session.secrets.id);
  EXPECT_EQ(authorization.ndPublicKey(), session.secrets.pk_nd);
}

TEST(NewDeviceApproval, AVerifiedSessionIsConsumedAndCannotApproveTwice) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  const auto approval = makeNdApproval(sas, session.secrets, nd_signer);

  const auto first = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, approval, verifyWith(nd_signer));
  EXPECT_TRUE(first.valid());
  EXPECT_TRUE(session.secrets.used);
  const auto second = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, approval, verifyWith(nd_signer));
  EXPECT_FALSE(second.valid());
}

TEST(NewDeviceApproval, ASignatureFromAWrongKeyIsRejected) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm honest;
  auth::sync::SoftwareTpm attacker;
  honest.createKey();
  attacker.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);

  auto approval = makeNdApproval(sas, session.secrets, attacker);
  approval.device_public_key = honest.getPubkey();  // claim an innocent identity

  EXPECT_FALSE(auth::sync::acceptNewDeviceApproval(session.secrets, sas, approval,
                                                   verifyWith(honest))
                   .valid());
}

TEST(NewDeviceApproval, ASasMismatchYieldsNoAuthorization) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  auto forged_sas = sas;
  forged_sas.back() = forged_sas.back() == '9' ? '8' : '9';

  EXPECT_FALSE(auth::sync::acceptNewDeviceApproval(
                   session.secrets, forged_sas,
                   makeNdApproval(sas, session.secrets, nd_signer), verifyWith(nd_signer))
                   .valid());
}

TEST(NewDeviceApproval, ACorruptedSignatureIsRejected) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  auto approval = makeNdApproval(sas, session.secrets, nd_signer);
  approval.signature.back() ^= 0x01;

  EXPECT_FALSE(auth::sync::acceptNewDeviceApproval(session.secrets, sas, approval,
                                                   verifyWith(nd_signer))
                   .valid());
}

// --- The vault-encryption path is unreachable without a valid authorization ---

TEST(TransferGate, AValidAuthorizationEncryptsAndThePeerDecrypts) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  const auto authorization = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, makeNdApproval(sas, session.secrets, nd_signer), verifyWith(nd_signer));

  const auto wire = auth::sync::encryptVaultForTransfer(sampleVault(), session.secrets.pk_nd,
                                                        authorization);
  const auto decrypted =
      auth::sync::decryptVaultFromTransfer(wire, session.secrets.sk_nd, session.secrets.id);

  ASSERT_EQ(decrypted.size(), 1U);
  EXPECT_EQ(decrypted.front().website, "https://example.test");
}

TEST(TransferGate, AnInvalidatedAuthorizationCannotEncrypt) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  auto authorization = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, makeNdApproval(sas, session.secrets, nd_signer), verifyWith(nd_signer));
  ASSERT_TRUE(authorization.valid());

  authorization.invalidate();

  EXPECT_THROW(auth::sync::encryptVaultForTransfer(sampleVault(), session.secrets.pk_nd,
                                                   authorization),
               std::runtime_error);
}

TEST(TransferGate, AnAuthorizationIsNotTransferableToAnotherSession) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  const auto other =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm nd_signer;
  nd_signer.createKey();
  const auto sas = auth::sync::computeSAS(session.secrets.pk_nd, session.secrets.id);
  const auto authorization = auth::sync::acceptNewDeviceApproval(
      session.secrets, sas, makeNdApproval(sas, session.secrets, nd_signer), verifyWith(nd_signer));

  // The gate must refuse to send the vault to a key the peer never proved it holds.
  EXPECT_THROW(auth::sync::encryptVaultForTransfer(sampleVault(), other.secrets.pk_nd,
                                                   authorization),
               std::runtime_error);
}

// --- sigma_ND must not be accepted against a session OD has not verified ---

TEST(OldDeviceApproval, ADenialOfAValidSignatureLeavesNoAuthorizationPath) {
  const auto now = Clock::time_point(std::chrono::seconds(2'000'000));
  auto session =
      auth::sync::beginNewDeviceSession("127.0.0.1:1", now, kLifetime);
  auth::sync::SoftwareTpm od_signer;
  od_signer.createKey();

  EXPECT_FALSE(auth::sync::acceptOldDeviceApproval(
      session.secrets, makeApproval(session.secrets, od_signer), now,
      [](const std::vector<uint8_t>&, const std::vector<uint8_t>&,
         const std::vector<uint8_t>&) { return false; })
      .valid());
  EXPECT_TRUE(session.secrets.used);
}

}  // namespace
