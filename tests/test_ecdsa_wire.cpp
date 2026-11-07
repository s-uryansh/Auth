#include "auth/ecdsa_wire.hpp"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

struct PKeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
};
using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDeleter>;

// Generate an ephemeral P-256 key and return (raw 64-byte signature over
// SHA256(message), 65-byte uncompressed public point), emulating exactly
// what a TPM 2.0 or Android Keystore backend exposes on the wire.
class P256Device {
public:
    P256Device() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!ctx) throw std::runtime_error("P256Device: no EC keyctx");
        char group[] = "P-256";
        const OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("group", group, 0),
            OSSL_PARAM_construct_end()};
        EVP_PKEY* generated = nullptr;
        if (EVP_PKEY_keygen_init(ctx) != 1 ||
            EVP_PKEY_CTX_set_params(ctx, const_cast<OSSL_PARAM*>(params)) != 1 ||
            EVP_PKEY_keygen(ctx, &generated) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("P256Device: keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);
        key_.reset(generated);
        if (key_ == nullptr) throw std::runtime_error("P256Device: null key");

        // Export the SEC1 point through OpenSSL's standard DER encoder and
        // let the code under test normalise it to the wire format. A key the
        // production helper cannot parse is itself a failure.
        unsigned char* der = nullptr;
        const int der_len = i2d_PUBKEY(key_.get(), &der);
        if (der_len <= 0 || !der) throw std::runtime_error("P256Device: DER export failed");
        const std::vector<uint8_t> der_vec(der, der + der_len);
        OPENSSL_free(der);
        point_ = auth::sync::ecdsaDerPublicKeyToPoint(der_vec);
        if (point_.empty())
            throw std::runtime_error(
                "P256Device: ecdsaDerPublicKeyToPoint rejected a freshly "
                "generated P-256 key");
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        RELEASE_ASSERT(ctx);
        RELEASE_ASSERT(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr,
                                          key_.get()) == 1);
        RELEASE_ASSERT(EVP_DigestSignUpdate(ctx, message.data(), message.size()) == 1);
        size_t der_len = 0;
        RELEASE_ASSERT(EVP_DigestSignFinal(ctx, nullptr, &der_len) == 1);
        std::vector<uint8_t> der(der_len);
        RELEASE_ASSERT(EVP_DigestSignFinal(ctx, der.data(), &der_len) == 1);
        EVP_MD_CTX_free(ctx);
        der.resize(der_len);
        return auth::sync::ecdsaDerSignatureToRaw(der);
    }

    const std::vector<uint8_t>& point() const { return point_; }

private:
    static void RELEASE_ASSERT(bool condition) {
        if (!condition) throw std::runtime_error("test key setup failed");
    }
    PKeyPtr key_;
    std::vector<uint8_t> point_;
};

TEST(EcdsaWireTest, RawSignatureRoundTripsThroughDerAndVerifies) {
    P256Device device;
    const std::vector<uint8_t> message = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    const auto raw = device.sign(message);
    ASSERT_EQ(raw.size(), 64u);

    const auto der = auth::sync::ecdsaRawSignatureToDer(raw);
    ASSERT_FALSE(der.empty());
    const auto back = auth::sync::ecdsaDerSignatureToRaw(der);
    EXPECT_EQ(back, raw);

    EXPECT_TRUE(auth::sync::ecdsaVerifySha256(message, raw, device.point()));
    std::vector<uint8_t> tampered = message;
    tampered[0] ^= 0x01;
    EXPECT_FALSE(auth::sync::ecdsaVerifySha256(tampered, raw, device.point()));
}

TEST(EcdsaWireTest, PublicKeyPointRoundTripsThroughSpkiDer) {
    P256Device device;
    const auto der = auth::sync::ecdsaPublicKeyPointToDer(device.point());
    ASSERT_FALSE(der.empty());
    EXPECT_EQ(auth::sync::ecdsaDerPublicKeyToPoint(der), device.point());
}

TEST(EcdsaWireTest, MalformedInputsAreRejected) {
    EXPECT_TRUE(auth::sync::ecdsaRawSignatureToDer(std::vector<uint8_t>(63, 0)).empty());
    EXPECT_TRUE(auth::sync::ecdsaDerSignatureToRaw(std::vector<uint8_t>{}).empty());
    EXPECT_TRUE(auth::sync::ecdsaDerSignatureToRaw(std::vector<uint8_t>{0x30, 0x03})
                    .empty());
    EXPECT_TRUE(auth::sync::ecdsaPublicKeyPointToDer(std::vector<uint8_t>(64, 0)).empty());
    EXPECT_TRUE(auth::sync::ecdsaPublicKeyPointToDer(
                    std::vector<uint8_t>(65, 0x05)).empty());
    EXPECT_TRUE(auth::sync::ecdsaDerPublicKeyToPoint(std::vector<uint8_t>{1, 2, 3}).empty());

    P256Device device;
    const auto message = std::vector<uint8_t>{'m'};
    const auto raw = device.sign(message);
    auto broken_raw = raw;
    broken_raw[10] ^= 0xff;
    EXPECT_FALSE(auth::sync::ecdsaVerifySha256(message, broken_raw, device.point()));
    EXPECT_FALSE(auth::sync::ecdsaVerifySha256(message, raw, std::vector<uint8_t>(65, 0)));
}

TEST(EcdsaWireTest, ShortCoordinatesArePaddedToFixedWidth) {
    // Build a raw signature whose s value has leading zero bytes and confirm
    // the padded raw form survives the DER round trip (the wire contract).
    std::vector<uint8_t> raw(64, 0);
    raw[31] = 0x01;              // r = 1
    raw[32] = 0x00;              // s has a leading zero byte
    raw[63] = 0x02;              // s = 2
    const auto der = auth::sync::ecdsaRawSignatureToDer(raw);
    ASSERT_FALSE(der.empty());
    EXPECT_EQ(auth::sync::ecdsaDerSignatureToRaw(der), raw);
}

}  // namespace
