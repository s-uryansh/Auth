#include "auth/sync_tpm.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <vector>

namespace {

const std::vector<uint8_t> kMessage{0x50, 0x68, 0x61, 0x73, 0x65, 0x20,
                                    0x46, 0x20, 0x61, 0x70, 0x70, 0x72,
                                    0x6f, 0x76, 0x61, 0x6c};

TEST(SoftwareTpmTest, IsExplicitlySoftwareOnly) {
  auth::sync::SoftwareTpm signer;

  EXPECT_FALSE(signer.hasTPM());
  EXPECT_STREQ(signer.backendName(), "software-only test signer");
}

TEST(SoftwareTpmTest, RequiresAKeyBeforeSigning) {
  auth::sync::SoftwareTpm signer;

  EXPECT_THROW(signer.sign(kMessage), std::runtime_error);
  EXPECT_TRUE(signer.getPubkey().empty());
}

TEST(SoftwareTpmTest, VerifiesOwnSignatureUsingOnlyTheSuppliedPublicKey) {
  auth::sync::SoftwareTpm signer;
  signer.createKey();

  const auto public_key = signer.getPubkey();
  const auto signature = signer.sign(kMessage);
  auth::sync::SoftwareTpm verifier;

  ASSERT_FALSE(public_key.empty());
  ASSERT_FALSE(signature.empty());
  EXPECT_TRUE(verifier.verify(kMessage, signature, public_key));
}

TEST(SoftwareTpmTest, RejectsWrongKeyMessageAndSignature) {
  auth::sync::SoftwareTpm signer;
  auth::sync::SoftwareTpm wrong_signer;
  signer.createKey();
  wrong_signer.createKey();

  const auto public_key = signer.getPubkey();
  const auto signature = signer.sign(kMessage);
  auto wrong_message = kMessage;
  wrong_message.back() ^= 0x01;
  auto wrong_signature = signature;
  wrong_signature.back() ^= 0x01;

  EXPECT_FALSE(signer.verify(kMessage, signature, wrong_signer.getPubkey()));
  EXPECT_FALSE(signer.verify(wrong_message, signature, public_key));
  EXPECT_FALSE(signer.verify(kMessage, wrong_signature, public_key));
}

TEST(SoftwareTpmTest, RecreatingAKeyReplacesTheSigningIdentity) {
  auth::sync::SoftwareTpm signer;
  signer.createKey();
  const auto first_public_key = signer.getPubkey();
  const auto first_signature = signer.sign(kMessage);

  signer.createKey();
  const auto second_public_key = signer.getPubkey();

  ASSERT_FALSE(first_public_key.empty());
  ASSERT_FALSE(second_public_key.empty());
  EXPECT_NE(first_public_key, second_public_key);
  EXPECT_FALSE(signer.verify(kMessage, first_signature, second_public_key));
}

TEST(SoftwareTpmTest, WipeRemovesSigningStateButPublicVerificationRemainsSafe) {
  auth::sync::SoftwareTpm signer;
  signer.createKey();
  const auto public_key = signer.getPubkey();
  const auto signature = signer.sign(kMessage);

  signer.wipe();

  EXPECT_TRUE(signer.getPubkey().empty());
  EXPECT_THROW(signer.sign(kMessage), std::runtime_error);
  EXPECT_TRUE(signer.verify(kMessage, signature, public_key));
}

TEST(NullTpmTest, HasSafeNoSignerSemanticsAndNeverAcceptsASignature) {
  auth::sync::NullTpm no_signer;

  EXPECT_FALSE(no_signer.hasTPM());
  EXPECT_STREQ(no_signer.backendName(), "no signing backend");
  EXPECT_NO_THROW(no_signer.createKey());
  EXPECT_TRUE(no_signer.getPubkey().empty());
  EXPECT_TRUE(no_signer.sign(kMessage).empty());
  EXPECT_FALSE(no_signer.verify(kMessage, {0x01}, {0x02}));
  EXPECT_FALSE(no_signer.verify({}, {}, {}));
  EXPECT_NO_THROW(no_signer.wipe());
}

}  // namespace
