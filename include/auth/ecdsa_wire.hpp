// ECDSA P-256 wire formats for Protocol 4 device signatures.
//
// Protocol 4 exchanges signatures and device public keys between different
// hardware backends (a TPM 2.0 on the desktop, the Android Keystore secure
// element on the phone). Both backends must therefore speak one common
// format:
//   - signature: fixed 64 bytes, r(32) || s(32), coordinates left-padded
//   - public key: uncompressed SEC1 point, 65 bytes, 0x04 || x(32) || y(32)
//   - scheme: ECDSA over NIST P-256 with SHA-256
// OpenSSL represents ECDSA signatures as DER and public keys as SPKI DER,
// so these helpers convert between the wire forms and OpenSSL objects.
#pragma once

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <cstdint>
#include <string>
#include <vector>

namespace auth {
namespace sync {

// 64-byte raw r||s -> DER ECDSA-Sig-Value. Returns empty on malformed input.
inline std::vector<uint8_t> ecdsaRawSignatureToDer(const std::vector<uint8_t>& raw) {
    if (raw.size() != 64) return {};
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    std::vector<uint8_t> der;
    if (!r || !s || !sig) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return der;
    }
    // On success ECDSA_SIG_set0 takes ownership of r and s.
    if (ECDSA_SIG_set0(sig, r, s) == 1) {
        const int len = i2d_ECDSA_SIG(sig, nullptr);
        if (len > 0) {
            der.resize(static_cast<size_t>(len));
            unsigned char* out = der.data();
            if (i2d_ECDSA_SIG(sig, &out) <= 0) der.clear();
        }
    }
    ECDSA_SIG_free(sig);
    return der;
}

// DER ECDSA-Sig-Value -> 64-byte raw r||s (coordinates padded).
// Returns empty on malformed or oversized input.
inline std::vector<uint8_t> ecdsaDerSignatureToRaw(const std::vector<uint8_t>& der) {
    if (der.empty() || der.size() > 128) return {};
    const unsigned char* in = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &in, static_cast<long>(der.size()));
    if (!sig) return {};
    const BIGNUM* r = ECDSA_SIG_get0_r(sig);
    const BIGNUM* s = ECDSA_SIG_get0_s(sig);
    std::vector<uint8_t> raw(64, 0);
    const bool ok = r && s &&
                    BN_bn2binpad(r, raw.data(), 32) == 32 &&
                    BN_bn2binpad(s, raw.data() + 32, 32) == 32;
    ECDSA_SIG_free(sig);
    return ok ? raw : std::vector<uint8_t>{};
}

// Uncompressed P-256 point (0x04||x||y) -> SPKI DER public key.
inline std::vector<uint8_t> ecdsaPublicKeyPointToDer(const std::vector<uint8_t>& point) {
    if (point.size() != 65 || point[0] != 0x04) return {};
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) return {};
    EVP_PKEY* pkey = nullptr;
    std::vector<uint8_t> der;
    const char group[] = "P-256";
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>(group), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  const_cast<uint8_t*>(point.data()),
                                                  point.size());
    params[2] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata_init(ctx) == 1 &&
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1 && pkey) {
        const int len = i2d_PUBKEY(pkey, nullptr);
        if (len > 0) {
            der.resize(static_cast<size_t>(len));
            unsigned char* out = der.data();
            if (i2d_PUBKEY(pkey, &out) <= 0) der.clear();
        }
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return der;
}

// SPKI DER public key -> uncompressed P-256 point (0x04||x||y).
inline std::vector<uint8_t> ecdsaDerPublicKeyToPoint(const std::vector<uint8_t>& der) {
    if (der.empty()) return {};
    const unsigned char* in = der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &in, static_cast<long>(der.size()));
    if (!pkey) return {};
    std::vector<uint8_t> point(65, 0);
    size_t len = 0;
    const bool ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                    point.data(), point.size(), &len) == 1 &&
                    len == 65 && point[0] == 0x04;
    EVP_PKEY_free(pkey);
    if (!ok) return {};
    return point;
}

// Verify an ECDSA-P256/SHA-256 signature over sha256(message) given the
// wire formats (raw 64-byte signature, 65-byte public key point).
inline bool ecdsaVerifySha256(const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& raw_signature,
                              const std::vector<uint8_t>& public_key_point) {
    const std::vector<uint8_t> der_point = ecdsaPublicKeyPointToDer(public_key_point);
    const std::vector<uint8_t> der_sig = ecdsaRawSignatureToDer(raw_signature);
    if (der_point.empty() || der_sig.empty()) return false;

    const unsigned char* in = der_point.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &in, static_cast<long>(der_point.size()));
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool valid = false;
    if (ctx &&
        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
        EVP_DigestVerify(ctx, der_sig.data(), der_sig.size(),
                         message.data(), message.size()) == 1) {
        valid = true;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return valid;
}

}  // namespace sync
}  // namespace auth
