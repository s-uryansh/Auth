// Protocol 4 transfer wire codecs.
//
// Byte-compatible home for the approval messages and the one-time vault
// payload encryption used by the QR Sync socket frames, extracted from the
// Qt UI so the wire contract can be unit-tested without widgets. The frame
// layout itself (4-byte big-endian length || type || 16-byte session id ||
// body) is produced by QRSyncTab::sendPlainFrame.
//
// Approval digests are defined in sync_protocol.hpp (Protocol 4, Section
// IV-C): sigma_OD covers H(ID || T || PKn), sigma_ND covers H(SAS || PKn ||
// ID). Device signatures follow the wire formats in ecdsa_wire.hpp when a
// hardware backend is used.
#pragma once

#include "auth/sync_protocol.hpp"
#include "auth/vault.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace auth {
namespace sync {

// AES-256-GCM payload: IV(12) || tag(16) || ciphertext. Used for the vault
// transfer body after the KEM ciphertext has established the one-time key.
inline std::vector<uint8_t> aesGcmEncryptPayload(const std::vector<uint8_t>& key,
                                                 const std::vector<uint8_t>& plaintext) {
    if (key.size() != 32) throw std::runtime_error("AES-GCM key must be 32 bytes");
    std::array<uint8_t, 12> iv{};
    if (RAND_bytes(iv.data(), 12) != 1) {
        throw std::runtime_error("RAND_bytes failed for GCM IV");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1;
    int outlen = 0;
    std::vector<uint8_t> ciphertext(plaintext.empty() ? 0 : plaintext.size() + 16);
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                               plaintext.data(),
                               static_cast<int>(plaintext.size())) == 1;
    }
    int finallen = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &finallen) == 1;
    }
    std::vector<uint8_t> tag(16);
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("AES-GCM encrypt failed");
    ciphertext.resize(outlen + finallen);
    std::vector<uint8_t> result;
    result.reserve(12 + 16 + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

inline std::vector<uint8_t> aesGcmDecryptPayload(const std::vector<uint8_t>& key,
                                                 const std::vector<uint8_t>& data) {
    if (key.size() != 32) throw std::runtime_error("AES-GCM key must be 32 bytes");
    if (data.size() < 12 + 16) {
        throw std::runtime_error("AES-GCM payload too short");
    }
    const uint8_t* iv = data.data();
    const uint8_t* tag_ptr = data.data() + 12;
    const uint8_t* ct_ptr = data.data() + 12 + 16;
    size_t ct_len = data.size() - 12 - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) == 1;
    int outlen = 0;
    std::vector<uint8_t> plaintext(ct_len + 16);
    if (ok && ct_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                               ct_ptr, static_cast<int>(ct_len)) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 const_cast<uint8_t*>(tag_ptr)) == 1;
    }
    int finallen = 0;
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &finallen) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("AES-GCM decrypt failed / tag verification failed");
    plaintext.resize(outlen + finallen);
    return plaintext;
}

// OdApproval wire serialization (kOdApproval frame body: OD -> ND).
inline std::vector<uint8_t> serializeOdApproval(const OdApproval& a) {
    std::vector<uint8_t> out;
    out.reserve(16 + 8 + 1184 + 2 + a.device_public_key.size() +
                2 + a.signature.size());
    out.insert(out.end(), a.id.begin(), a.id.end());
    uint64_t epoch = std::chrono::duration_cast<std::chrono::seconds>(
        a.expiry.time_since_epoch()).count();
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((epoch >> (static_cast<uint64_t>(i) * 8)) & 0xff));
    out.insert(out.end(), a.pk_nd.begin(), a.pk_nd.end());
    uint16_t pk_len = static_cast<uint16_t>(a.device_public_key.size());
    out.push_back(static_cast<uint8_t>(pk_len >> 8));
    out.push_back(static_cast<uint8_t>(pk_len & 0xff));
    out.insert(out.end(), a.device_public_key.begin(), a.device_public_key.end());
    uint16_t sig_len = static_cast<uint16_t>(a.signature.size());
    out.push_back(static_cast<uint8_t>(sig_len >> 8));
    out.push_back(static_cast<uint8_t>(sig_len & 0xff));
    out.insert(out.end(), a.signature.begin(), a.signature.end());
    return out;
}

inline OdApproval deserializeOdApproval(const std::vector<uint8_t>& data) {
    OdApproval a;
    size_t pos = 0;
    if (data.size() < 16 + 8 + 1184 + 2 + 2)
        throw std::runtime_error("OdApproval too short");
    std::copy(data.begin(), data.begin() + 16, a.id.begin());
    pos = 16;
    uint64_t epoch = 0;
    for (int i = 0; i < 8; ++i)
        epoch = (epoch << 8) | static_cast<uint64_t>(data[pos++]);
    a.expiry = std::chrono::system_clock::time_point(
        std::chrono::seconds(static_cast<int64_t>(epoch)));
    std::copy(data.begin() + pos, data.begin() + pos + 1184, a.pk_nd.begin());
    pos += 1184;
    if (data.size() < pos + 2) throw std::runtime_error("OdApproval truncated (pk len)");
    uint16_t pk_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (data.size() < pos + pk_len) throw std::runtime_error("OdApproval truncated (pk)");
    a.device_public_key.assign(data.begin() + pos, data.begin() + pos + pk_len);
    pos += pk_len;
    if (data.size() < pos + 2) throw std::runtime_error("OdApproval truncated (sig len)");
    uint16_t sig_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (data.size() < pos + sig_len) throw std::runtime_error("OdApproval truncated (sig)");
    a.signature.assign(data.begin() + pos, data.begin() + pos + sig_len);
    return a;
}

// NdApproval wire serialization (kNdApproval frame body: ND -> OD).
inline std::vector<uint8_t> serializeNdApproval(const NdApproval& a) {
    std::vector<uint8_t> out;
    out.reserve(2 + a.device_public_key.size() + 2 + a.signature.size());
    uint16_t pk_len = static_cast<uint16_t>(a.device_public_key.size());
    out.push_back(static_cast<uint8_t>(pk_len >> 8));
    out.push_back(static_cast<uint8_t>(pk_len & 0xff));
    out.insert(out.end(), a.device_public_key.begin(), a.device_public_key.end());
    uint16_t sig_len = static_cast<uint16_t>(a.signature.size());
    out.push_back(static_cast<uint8_t>(sig_len >> 8));
    out.push_back(static_cast<uint8_t>(sig_len & 0xff));
    out.insert(out.end(), a.signature.begin(), a.signature.end());
    return out;
}

inline NdApproval deserializeNdApproval(const std::vector<uint8_t>& data) {
    NdApproval a;
    size_t pos = 0;
    if (data.size() < 4) throw std::runtime_error("NdApproval too short");
    uint16_t pk_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (data.size() < pos + pk_len) throw std::runtime_error("NdApproval truncated (pk)");
    a.device_public_key.assign(data.begin() + pos, data.begin() + pos + pk_len);
    pos += pk_len;
    if (data.size() < pos + 2) throw std::runtime_error("NdApproval truncated (sig len)");
    uint16_t sig_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (data.size() < pos + sig_len) throw std::runtime_error("NdApproval truncated (sig)");
    a.signature.assign(data.begin() + pos, data.begin() + pos + sig_len);
    return a;
}

}  // namespace sync
}  // namespace auth
