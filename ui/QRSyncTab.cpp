#include "QRSyncTab.h"

#include "PasswordManagerTab.h"
#include "SensitiveData.h"

#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"
#include "auth/tpm2.hpp"

#include <QAbstractSocket>
#include <QCamera>
#include <QCameraDevice>
#include <QCameraFormat>
#include <QCoreApplication>
#include <QFont>
#include <QClipboard>
#include <QDesktopServices>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMediaCaptureSession>
#include <QMediaDevices>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QPixmap>
#include <QPermissions>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTimer>
#include <QVideoFrame>
#include <QVideoSink>
#include <QVBoxLayout>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>
#include <QtConcurrentRun>

#include <ZXing/ReadBarcode.h>
#include <ZXing/ReaderOptions.h>
#include <ZXing/BarcodeFormat.h>
#include <ZXing/ImageView.h>
#include <ZXing/MultiFormatWriter.h>
#include <ZXing/BitMatrix.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <oqs/kem.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using auth::sync::computeSAS;
using auth::sync::deserializeQR;
using auth::sync::encryptVaultForTransfer;
using auth::sync::decryptVaultFromTransfer;
using auth::sync::kemDecapsulate;
using auth::sync::kemEncapsulate;
using auth::sync::mergeVaultEntries;
using auth::sync::oldDeviceApprovalDigest;
using auth::sync::newDeviceApprovalDigest;
using auth::sync::acceptOldDeviceApproval;
using auth::sync::acceptNewDeviceApproval;
using auth::sync::scanPairingQR;
using auth::sync::serializeQR;
using auth::sync::SessionSecrets;
using auth::sync::SoftwareTpm;
using auth::sync::Tpm2Tpm;
using auth::sync::TpmInterface;

namespace {

// QR content is Base64-wrapped so binary protocol fields (PK_n, ID, expiry)
// survive the scan. The envelope tags the code so unrelated QRs are ignored.
constexpr const char* kAuthQrPrefix = "AUTHQR:";

std::string base64Encode(const std::vector<uint8_t>& in) {
    if (in.empty()) return {};
    const int out_len = 4 * ((static_cast<int>(in.size()) + 2) / 3);
    std::string out(out_len, '\0');
    const int n = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]), in.data(),
        static_cast<int>(in.size()));
    out.resize(n);
    return out;
}

QScrollArea* makeScrollablePage(QWidget* content) {
    auto* scroll = new QScrollArea;
    scroll->setWidget(content);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    return scroll;
}

QByteArray decodePairingQrImage(QImage image, bool thorough_fallback) {
    if (image.isNull()) return {};
    QImage gray = image.convertToFormat(QImage::Format_Grayscale8);
    if (gray.isNull()) return {};
    const ZXing::ImageView view(gray.constBits(), gray.width(), gray.height(),
                                ZXing::ImageFormat::Lum, gray.bytesPerLine());
    auto result = ZXing::ReadBarcode(
        view, ZXing::ReaderOptions()
                  .setFormats(ZXing::BarcodeFormat::QRCode)
                  .setTryHarder(false)
                  .setTryRotate(true)
                  .setTryInvert(false)
                  .setTryDownscale(false));
    if (!result.isValid() && thorough_fallback) {
        result = ZXing::ReadBarcode(
            view, ZXing::ReaderOptions()
                      .setFormats(ZXing::BarcodeFormat::QRCode)
                      .setTryHarder(true)
                      .setTryRotate(true)
                      .setTryInvert(true)
                      .setTryDownscale(true));
    }
    if (!result.isValid()) return {};

    const auto& bytes = result.bytes();
    const QByteArray envelope(reinterpret_cast<const char*>(bytes.data()),
                              static_cast<qsizetype>(bytes.size()));
    const QByteArray prefix = QByteArray::fromStdString(kAuthQrPrefix);
    if (!envelope.startsWith(prefix) || envelope.size() <= prefix.size()) return {};
    return QByteArray::fromBase64(
        envelope.mid(prefix.size()), QByteArray::AbortOnBase64DecodingErrors);
}

QString reachableLanAddress() {
    for (const QHostAddress& addr : QNetworkInterface::allAddresses()) {
        if (addr.protocol() == QAbstractSocket::IPv4Protocol &&
            !addr.isLoopback() && !addr.isNull()) {
            return addr.toString();
        }
    }
    return QStringLiteral("127.0.0.1");
}

std::vector<uint8_t> aesGcmEncrypt(const std::vector<uint8_t>& key,
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

std::vector<uint8_t> aesGcmDecrypt(const std::vector<uint8_t>& key,
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

// OdApproval wire serialization (for kOdApproval frame: OD -> ND)
std::vector<uint8_t> serializeOdApproval(const auth::sync::OdApproval& a) {
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

auth::sync::OdApproval deserializeOdApproval(const std::vector<uint8_t>& data) {
    auth::sync::OdApproval a;
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

// NdApproval wire serialization (for kNdApproval frame: ND -> OD)
std::vector<uint8_t> serializeNdApproval(const auth::sync::NdApproval& a) {
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

auth::sync::NdApproval deserializeNdApproval(const std::vector<uint8_t>& data) {
    auth::sync::NdApproval a;
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

} // namespace

// ---------------------------------------------------------------------------
// Constructor / destructor
// ---------------------------------------------------------------------------

QRSyncTab::QRSyncTab(PasswordManagerTab* password_manager, QWidget* parent)
    : QWidget(parent),
      password_manager_(password_manager),
      pages_(new QStackedWidget(this)),
      decode_watcher_(new QFutureWatcher<QByteArray>(this)),
      expiry_timer_(new QTimer(this)) {

    // Allocate all UI widgets up front. These raw-pointer members are not
    // initialized in the member-initializer list, so they must be constructed
    // here before the screen-setup code below dereferences them.
    role_page_ = new QWidget(pages_);
    role_label_ = new QLabel("Which device is this?", role_page_);
    new_device_btn_ = new QPushButton("New Device", role_page_);
    old_device_btn_ = new QPushButton("Old Device", role_page_);

    setup_page_ = new QWidget(pages_);
    setup_label_ = new QLabel("Prepare this device", setup_page_);
    start_btn_ = new QPushButton("Start", setup_page_);

    waiting_qr_page_ = new QWidget(pages_);
    waiting_qr_label_ = new QLabel("Scan this code with your new device.", waiting_qr_page_);
    qr_label_ = new QLabel(waiting_qr_page_);
    qr_countdown_label_ = new QLabel("Expires in 5:00", waiting_qr_page_);
    refresh_qr_btn_ = new QPushButton("Refresh QR", waiting_qr_page_);

    scanning_page_ = new QWidget(pages_);
    scanning_page_->setObjectName("qrSyncScanningPage");
    scanning_label_ = new QLabel("Scan the code on your old device.", scanning_page_);
    scanner_countdown_label_ = new QLabel("", scanning_page_);
    camera_viewfinder_ = new QLabel(scanning_page_);
    scan_qr_btn_ = new QPushButton("Start Camera", scanning_page_);
    scan_cancel_btn_ = new QPushButton("Cancel", scanning_page_);

    connected_page_ = new QWidget(pages_);
    connected_label_ = new QLabel("Connecting…", connected_page_);
    connected_cancel_btn_ = new QPushButton("Cancel", connected_page_);

    sas_page_ = new QWidget(pages_);
    sas_label_ = new QLabel("Do these codes match?", sas_page_);
    od_sas_label_ = new QLabel(sas_page_);
    codes_match_btn_ = new QPushButton("Match", sas_page_);
    codes_differ_btn_ = new QPushButton("Don't match", sas_page_);
    sas_cancel_btn_ = new QPushButton("Cancel", sas_page_);

    approving_od_page_ = new QWidget(pages_);
    approving_od_label_ = new QLabel("Approve pairing on this device?", approving_od_page_);
    od_approve_btn_ = new QPushButton("Approve", approving_od_page_);
    od_approve_cancel_btn_ = new QPushButton("Cancel", approving_od_page_);

    approving_nd_page_ = new QWidget(pages_);
    approving_nd_label_ = new QLabel("Waiting for the old device to approve…", approving_nd_page_);
    nd_approve_btn_ = new QPushButton("Approve", approving_nd_page_);
    nd_approve_cancel_btn_ = new QPushButton("Cancel", approving_nd_page_);

    transferring_page_ = new QWidget(pages_);
    transferring_label_ = new QLabel("Transferring vault…", transferring_page_);
    transfer_cancel_btn_ = new QPushButton("Cancel", transferring_page_);

    done_page_ = new QWidget(pages_);
    done_label_ = new QLabel("Sync complete", done_page_);
    done_btn_ = new QPushButton("Done", done_page_);

    error_page_ = new QWidget(pages_);
    error_label_ = new QLabel(error_page_);
    error_retry_btn_ = new QPushButton("Try again", error_page_);

    status_label_ = new QLabel("Ready", this);

    capture_session_ = new QMediaCaptureSession(this);
    video_sink_ = new QVideoSink(this);

    setWindowTitle("QR Sync");

    // ---------- Role screen ----------
    auto* role_layout = new QVBoxLayout(role_page_);
    role_label_->setAlignment(Qt::AlignCenter);
    QFont role_font = role_label_->font();
    role_font.setPointSize(15);
    role_label_->setFont(role_font);
    role_layout->addWidget(role_label_);
    role_layout->addSpacing(24);
    new_device_btn_->setMinimumHeight(44);
    old_device_btn_->setMinimumHeight(44);
    role_layout->addWidget(new_device_btn_);
    role_layout->addWidget(old_device_btn_);
    role_layout->addStretch();

    // ---------- Setup screen ----------
    auto* setup_layout = new QVBoxLayout(setup_page_);
    setup_label_->setAlignment(Qt::AlignCenter);
    setup_label_->setWordWrap(true);
    setup_layout->addWidget(setup_label_);
    setup_layout->addSpacing(24);
    start_btn_->setMinimumHeight(44);
    setup_layout->addWidget(start_btn_);
    setup_layout->addStretch();

    // ---------- Waiting QR screen ----------
    auto* wqr_layout = new QVBoxLayout(waiting_qr_page_);
    waiting_qr_label_->setAlignment(Qt::AlignCenter);
    wqr_layout->addWidget(waiting_qr_label_);
    qr_label_->setAlignment(Qt::AlignCenter);
    qr_label_->setMinimumSize(300, 300);
    wqr_layout->addWidget(qr_label_, 0, Qt::AlignCenter);
    qr_countdown_label_->setObjectName("qrExpiryCountdown");
    qr_countdown_label_->setAlignment(Qt::AlignCenter);
    wqr_layout->addWidget(qr_countdown_label_);
    refresh_qr_btn_->setMinimumHeight(40);
    wqr_layout->addWidget(refresh_qr_btn_);
    wqr_layout->addStretch();

    // ---------- Scanning screen ----------
    auto* scan_layout = new QVBoxLayout(scanning_page_);
    scanning_label_->setAlignment(Qt::AlignCenter);
    scan_layout->addWidget(scanning_label_);
    scanner_countdown_label_->setAlignment(Qt::AlignCenter);
    scan_layout->addWidget(scanner_countdown_label_);
    camera_viewfinder_->setAlignment(Qt::AlignCenter);
    camera_viewfinder_->setMinimumSize(320, 240);
    camera_viewfinder_->setStyleSheet("QLabel { background: #000; }");
    scan_layout->addWidget(camera_viewfinder_, 1);
    auto* scan_btns = new QHBoxLayout;
    scan_qr_btn_->setMinimumHeight(44);
    scan_cancel_btn_->setMinimumHeight(44);
    scan_btns->addWidget(scan_qr_btn_);
    scan_btns->addWidget(scan_cancel_btn_);
    scan_layout->addLayout(scan_btns);

    // ---------- Connected screen ----------
    auto* conn_layout = new QVBoxLayout(connected_page_);
    connected_label_->setAlignment(Qt::AlignCenter);
    conn_layout->addWidget(connected_label_);
    connected_cancel_btn_->setMinimumHeight(44);
    conn_layout->addWidget(connected_cancel_btn_);

    // ---------- SAS screen ----------
    auto* sas_layout = new QVBoxLayout(sas_page_);
    sas_label_->setAlignment(Qt::AlignCenter);
    sas_layout->addWidget(sas_label_);
    od_sas_label_->setAlignment(Qt::AlignCenter);
    QFont sas_font = od_sas_label_->font();
    sas_font.setPointSize(16);
    sas_font.setStyleHint(QFont::Monospace);
    od_sas_label_->setFont(sas_font);
    od_sas_label_->setMinimumHeight(60);
    od_sas_label_->setWordWrap(true);
    sas_layout->addWidget(od_sas_label_);
    auto* sas_btns = new QHBoxLayout;
    codes_match_btn_->setMinimumHeight(44);
    codes_differ_btn_->setMinimumHeight(44);
    sas_cancel_btn_->setMinimumHeight(44);
    sas_btns->addWidget(codes_match_btn_);
    sas_btns->addWidget(codes_differ_btn_);
    sas_layout->addLayout(sas_btns);
    sas_layout->addWidget(sas_cancel_btn_);

    // ---------- Approving OD screen ----------
    auto* ao_layout = new QVBoxLayout(approving_od_page_);
    approving_od_label_->setAlignment(Qt::AlignCenter);
    ao_layout->addWidget(approving_od_label_);
    od_approve_btn_->setMinimumHeight(44);
    od_approve_cancel_btn_->setMinimumHeight(44);
    ao_layout->addWidget(od_approve_btn_);
    ao_layout->addWidget(od_approve_cancel_btn_);

    // ---------- Approving ND screen ----------
    auto* an_layout = new QVBoxLayout(approving_nd_page_);
    approving_nd_label_->setAlignment(Qt::AlignCenter);
    an_layout->addWidget(approving_nd_label_);
    nd_approve_btn_->setMinimumHeight(44);
    nd_approve_cancel_btn_->setMinimumHeight(44);
    an_layout->addWidget(nd_approve_btn_);
    an_layout->addWidget(nd_approve_cancel_btn_);

    // ---------- Transferring screen ----------
    auto* tr_layout = new QVBoxLayout(transferring_page_);
    transferring_label_->setAlignment(Qt::AlignCenter);
    tr_layout->addWidget(transferring_label_);
    transfer_cancel_btn_->setMinimumHeight(44);
    tr_layout->addWidget(transfer_cancel_btn_);

    // ---------- Done screen ----------
    auto* done_layout = new QVBoxLayout(done_page_);
    done_label_->setAlignment(Qt::AlignCenter);
    done_layout->addWidget(done_label_);
    done_btn_->setMinimumHeight(44);
    done_layout->addWidget(done_btn_);

    // ---------- Error screen ----------
    auto* err_layout = new QVBoxLayout(error_page_);
    error_label_->setAlignment(Qt::AlignCenter);
    error_label_->setWordWrap(true);
    err_layout->addWidget(error_label_);
    error_retry_btn_->setMinimumHeight(44);
    err_layout->addWidget(error_retry_btn_);

    pages_->addWidget(makeScrollablePage(role_page_));
    pages_->addWidget(makeScrollablePage(setup_page_));
    pages_->addWidget(makeScrollablePage(waiting_qr_page_));
    pages_->addWidget(makeScrollablePage(scanning_page_));
    pages_->addWidget(makeScrollablePage(connected_page_));
    pages_->addWidget(makeScrollablePage(sas_page_));
    pages_->addWidget(makeScrollablePage(approving_od_page_));
    pages_->addWidget(makeScrollablePage(approving_nd_page_));
    pages_->addWidget(makeScrollablePage(transferring_page_));
    pages_->addWidget(makeScrollablePage(done_page_));
    pages_->addWidget(makeScrollablePage(error_page_));

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(pages_);
    layout->addWidget(status_label_);

    // ---------- Signal connections ----------
    connect(new_device_btn_, &QPushButton::clicked,
            this, [this]() { onRoleSelected(false); });
    connect(old_device_btn_, &QPushButton::clicked,
            this, [this]() { onRoleSelected(true); });
    connect(start_btn_, &QPushButton::clicked, this, &QRSyncTab::onStartClicked);
    connect(refresh_qr_btn_, &QPushButton::clicked, this, &QRSyncTab::onRefreshQRClicked);
    connect(scan_qr_btn_, &QPushButton::clicked, this, &QRSyncTab::onScanQRClicked);
    connect(scan_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(connected_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(codes_match_btn_, &QPushButton::clicked, this, &QRSyncTab::onCodesMatchClicked);
    connect(codes_differ_btn_, &QPushButton::clicked, this, &QRSyncTab::onCodesDifferClicked);
    connect(sas_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(od_approve_btn_, &QPushButton::clicked, this, &QRSyncTab::onApproveClicked);
    connect(od_approve_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(nd_approve_btn_, &QPushButton::clicked, this, &QRSyncTab::onApproveClicked);
    connect(nd_approve_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(transfer_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(done_btn_, &QPushButton::clicked, this, &QRSyncTab::onDoneClicked);
    connect(error_retry_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);

    // ---------- Network ----------
    server_ = new QTcpServer(this);

    connect(server_, &QTcpServer::newConnection, this, [this]() {
        QTcpSocket* client = server_->nextPendingConnection();
        if (!client) return;
        if (od_mode_ && isSessionExpired()) {
            client->abort();
            client->deleteLater();
            expireSession();
            return;
        }
        if (socket_) {
            client->disconnectFromHost();
            client->deleteLater();
            return;
        }
        socket_ = client;
        connect(socket_, &QTcpSocket::readyRead, this, &QRSyncTab::handleSocketData);
        connect(socket_, &QTcpSocket::disconnected, this, [this]() {
            socket_->deleteLater();
            socket_ = nullptr;
            updateStatus("Peer disconnected");
        });
        connect(socket_, static_cast<void (QAbstractSocket::*)(QAbstractSocket::SocketError)>(
                             &QAbstractSocket::errorOccurred),
                this, [this](QAbstractSocket::SocketError) {
                    showError(QString("Network error: %1")
                                  .arg(socket_ ? socket_->errorString()
                                               : QString("unknown socket")));
                });
        updateStatus("New device connected");
        if (pages_->currentIndex() == static_cast<int>(WaitingQR)) {
            switchScreen(SAS);
            od_sas_label_->setText(formatSAS(od_sas_code_));
            updateStatus("Check the codes match");
        }
    });

    // ---------- Timers ----------
    expiry_timer_->setInterval(1000);
    connect(expiry_timer_, &QTimer::timeout, this, [this]() {
        updateSessionCountdown();
    });

    // ---------- Camera ----------
    capture_session_->setVideoOutput(video_sink_);
    connect(video_sink_, &QVideoSink::videoFrameChanged, this,
            &QRSyncTab::processCameraFrame);
    connect(decode_watcher_, &QFutureWatcher<QByteArray>::finished, this, [this]() {
        decode_pending_ = false;

        QByteArray decoded;
        try {
            decoded = decode_watcher_->result();
        } catch (const std::exception&) {
            return;
        }
        if (decode_generation_ != scan_generation_ ||
            pages_->currentIndex() != static_cast<int>(Scanning) ||
            qr_decoded_ || decoded.isEmpty())
            return;

        qr_decoded_ = true;
        const std::vector<uint8_t> bytes(decoded.cbegin(), decoded.cend());
        stopCameraScanner();
        handleScannedQr(bytes);
    });

    // ---------- TPM ----------
    try {
        tpm_ = std::make_unique<SoftwareTpm>();
    } catch (const std::exception& e) {
        tpm_ = std::make_unique<auth::sync::NullTpm>();
        updateStatus(QString("TPM backend unavailable: %1").arg(e.what()));
    }

    switchScreen(Role);
}

QRSyncTab::~QRSyncTab() {
    wipeSession();
    if (camera_) camera_->stop();
    if (server_) server_->close();
    if (socket_) socket_->disconnectFromHost();
}

void QRSyncTab::createClientSocket() {
    if (socket_) return;
    socket_ = new QTcpSocket(this);
    connect(socket_, &QTcpSocket::readyRead, this, &QRSyncTab::handleSocketData);
    connect(socket_, &QTcpSocket::disconnected, this, [this]() {
        if (!socket_) return;
        socket_->deleteLater();
        socket_ = nullptr;
        if (pages_->currentWidget() != error_page_ &&
            pages_->currentWidget() != done_page_) {
            updateStatus("Peer disconnected");
        }
    });
    connect(socket_, &QAbstractSocket::errorOccurred, this,
            [this](QAbstractSocket::SocketError) {
                showError(QString("Network error: %1")
                              .arg(socket_ ? socket_->errorString()
                                           : QString("unknown socket")));
            });
}

void QRSyncTab::switchScreen(Screen screen) {
    pages_->setCurrentIndex(static_cast<int>(screen));
    switch (screen) {
        case Role:
            updateStatus("Choose which device this is");
            break;
        case Setup:
            updateStatus(od_mode_
                             ? "Old device: generate a pairing code"
                             : "New device: scan the pairing code");
            break;
        case WaitingQR:
            updateStatus("Old device: waiting for the new device to scan");
            break;
        case Scanning:
            updateStatus("New device: scan the code on the old device");
            break;
        case Connected:
            updateStatus("Connecting…");
            break;
        case SAS:
            updateStatus("Check the codes on both devices match");
            break;
        case ApprovingOD:
            updateStatus("Old device: approve the pairing");
            break;
        case ApprovingND:
            updateStatus("New device: waiting for the old device to approve");
            break;
        case Transferring:
            updateStatus("Transferring vault…");
            break;
        case Done:
            updateStatus("Sync complete");
            break;
        case Error:
            break;
    }
}

void QRSyncTab::updateStatus(const QString& status) {
    status_label_->setText(status);
}

void QRSyncTab::showError(const QString& message) {
    error_label_->setText(message);
    switchScreen(Error);
}

void QRSyncTab::updateSessionCountdown() {
    const auto deadline = od_mode_ ? od_expiry_ : expiry_;
    if (deadline == std::chrono::system_clock::time_point{}) {
        expiry_timer_->stop();
        return;
    }

    if (isSessionExpired()) {
        expireSession();
        return;
    }

    const qint64 remaining_ms = session_duration_ms_ - session_elapsed_.elapsed();
    const qint64 remaining = (remaining_ms + 999) / 1000;
    const auto minutes = remaining / 60;
    const auto seconds = remaining % 60;
    const QString text = QString("Expires in %1:%2")
                             .arg(minutes)
                             .arg(seconds, 2, 10, QChar('0'));
    if (od_mode_) {
        qr_countdown_label_->setText(text);
    } else {
        scanner_countdown_label_->setText(text);
    }
}

bool QRSyncTab::isSessionExpired() const {
    const auto deadline = od_mode_ ? od_expiry_ : expiry_;
    if (deadline == std::chrono::system_clock::time_point{}) return false;
    return std::chrono::system_clock::now() >= deadline ||
           !session_elapsed_.isValid() ||
           session_elapsed_.elapsed() >= session_duration_ms_;
}

void QRSyncTab::expireSession() {
    constexpr auto kExpiredMessage = "QR Sync session expired. Generate a new QR to continue.";
    wipeSession();
    qr_label_->clear();
    qr_countdown_label_->setText("Expired");
    scanner_countdown_label_->setText("Expired");
    showError(kExpiredMessage);
    emit syncFinished(false, QString::fromLatin1(kExpiredMessage));
}

void QRSyncTab::wipeSession() {
    stopCameraScanner();
    od_mode_ = false;
    new_device_approved_ = false;
    old_device_approved_ = false;
    qr_decoded_ = false;

    qr_payload_ = auth::sync::QRPayload{};
    pk_nd_.fill(0);
    sk_nd_.fill(0);
    id_.fill(0);
    expiry_ = std::chrono::system_clock::time_point{};
    sas_code_.clear();
    session_ = SessionSecrets{};
    nd_auth_ = auth::sync::NdAuthorization{};

    od_pk_nd_.fill(0);
    od_id_.fill(0);
    od_expiry_ = std::chrono::system_clock::time_point{};
    od_sas_code_.clear();
    od_session_ = SessionSecrets{};
    od_auth_ = auth::sync::NdAuthorization{};
    od_pk_od_.clear();
    od_sigma_od_.clear();

    if (!noise_key_.empty()) {
        OPENSSL_cleanse(noise_key_.data(), noise_key_.size());
        noise_key_.clear();
    }
    if (tpm_) tpm_->wipe();

    socket_rx_.clear();
    vault_data_.clear();
    ui::wipeVaultEntries(transfer_entries_);
    transfer_entries_.clear();

    if (server_) server_->close();
    if (socket_) {
        socket_->disconnect(this);
        socket_->abort();
        socket_->deleteLater();
        socket_ = nullptr;
    }
    expiry_timer_->stop();
    session_elapsed_.invalidate();
    session_duration_ms_ = 0;
}

QString QRSyncTab::formatSAS(const std::string& sas) {
    QString result;
    for (size_t i = 0; i < sas.size(); ++i) {
        result += QString("%1").arg(static_cast<unsigned char>(sas[i]), 2, 16,
                                    QLatin1Char('0'));
        if ((i + 1) % 4 == 0 && i + 1 < sas.size()) result += QLatin1Char(' ');
    }
    return result.toUpper();
}

void QRSyncTab::renderQRBitmap(const std::vector<uint8_t>& qr_data) {
    const std::string text = std::string(kAuthQrPrefix) + base64Encode(qr_data);
    ZXing::MultiFormatWriter writer(ZXing::BarcodeFormat::QRCode);
    writer.setEncoding(ZXing::CharacterSet::BINARY);
    writer.setEccLevel(0);
    writer.setMargin(4);
    const qreal device_pixel_ratio = qr_label_->devicePixelRatioF();
    const QSize logical_size = qr_label_->size().expandedTo(QSize(300, 300));
    const QSize pixel_size = logical_size * device_pixel_ratio;
    const ZXing::BitMatrix matrix =
        writer.encode(text, pixel_size.width(), pixel_size.height());
    const int w = matrix.width();
    const int h = matrix.height();
    QImage img(w, h, QImage::Format_RGB32);
    for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
            img.setPixel(x, y, matrix.get(x, y) ? qRgb(0, 0, 0)
                                                : qRgb(255, 255, 255));
        }
    }
    QPixmap pixmap = QPixmap::fromImage(img);
    pixmap.setDevicePixelRatio(device_pixel_ratio);
    qr_label_->setPixmap(pixmap);
}

std::vector<auth::VaultEntry> QRSyncTab::loadLocalVault() {
    QString error;
    if (!password_manager_->exportVaultEntriesForSync(transfer_entries_, error)) {
        showError(error);
        return {};
    }
    if (transfer_entries_.empty()) {
        showError("The source vault has no credentials to transfer");
        return {};
    }
    updateStatus(QString("Vault loaded: %1 credential(s)")
                     .arg(transfer_entries_.size()));
    return transfer_entries_;
}

void QRSyncTab::saveLocalVault(const std::vector<auth::VaultEntry>& entries) {
    QString error;
    if (!password_manager_->importVaultEntriesFromSync(entries, error)) {
        showError(error);
        return;
    }
    updateStatus(QString("Vault sync complete: %1 credential(s)")
                     .arg(entries.size()));
}

QByteArray QRSyncTab::sessionId() const {
    if (od_mode_) {
        return QByteArray(reinterpret_cast<const char*>(od_id_.data()),
                          static_cast<int>(od_id_.size()));
    }
    return QByteArray(reinterpret_cast<const char*>(id_.data()),
                      static_cast<int>(id_.size()));
}

void QRSyncTab::sendPlainFrame(quint8 type, const QByteArray& payload) {
    if (!socket_ || socket_->state() != QAbstractSocket::ConnectedState) {
        showError("Not connected to peer");
        return;
    }
    QByteArray frame;
    frame.reserve(4 + 1 + 16 + payload.size());
    quint32 len = static_cast<quint32>(1 + 16 + payload.size());
    char len_buf[4];
    len_buf[0] = static_cast<char>((len >> 24) & 0xFF);
    len_buf[1] = static_cast<char>((len >> 16) & 0xFF);
    len_buf[2] = static_cast<char>((len >> 8) & 0xFF);
    len_buf[3] = static_cast<char>(len & 0xFF);
    frame.append(len_buf, 4);
    frame.append(static_cast<char>(type));
    frame.append(sessionId());
    frame.append(payload);
    socket_->write(frame);
    if (!socket_->waitForBytesWritten(1000)) {
        showError("Failed to write frame to peer");
    }
}

// ---------------------------------------------------------------------------
// Role / start / cancel
// ---------------------------------------------------------------------------

void QRSyncTab::onRoleSelected(bool old_device) {
    wipeSession();
    od_mode_ = old_device;
    if (od_mode_) {
        switchScreen(Setup);
        setup_label_->setText("Generate a pairing code on this device.");
        start_btn_->setText("Generate QR");
    } else {
        scanning_label_->setText("Requesting camera access…");
        switchScreen(Scanning);
        startCameraScanner();
    }
}

void QRSyncTab::onStartClicked() {
    if (od_mode_) {
        try {
            loadLocalVault();
            if (transfer_entries_.empty()) return;

            OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
            if (!kem) throw std::runtime_error("OQS_KEM_new failed");
            if (OQS_KEM_keypair(kem, od_pk_nd_.data(), sk_nd_.data()) != OQS_SUCCESS) {
                OQS_KEM_free(kem);
                throw std::runtime_error("OQS_KEM_keypair failed");
            }
            OQS_KEM_free(kem);

            if (RAND_bytes(od_id_.data(), static_cast<int>(od_id_.size())) != 1) {
                throw std::runtime_error("RAND_bytes failed for session ID");
            }
            od_session_.id = od_id_;
            od_session_.pk_nd = od_pk_nd_;
            od_session_.sk_nd = sk_nd_;
            od_session_.used = false;

            od_sas_code_ = computeSAS(od_pk_nd_, od_id_);
            od_session_.sas = od_sas_code_;

            if (!server_->isListening() && !server_->listen(QHostAddress::Any, 0)) {
                throw std::runtime_error("Failed to start TCP listen socket");
            }
            quint16 port = static_cast<quint16>(server_->serverPort());
            QString host = reachableLanAddress();
            QString conn_info = QString("%1:%2").arg(host).arg(port);
            od_expiry_ = std::chrono::system_clock::now() +
                         std::chrono::seconds(auth::sync::kSessionExpirySeconds);
            od_session_.expiry = od_expiry_;

            auth::sync::QRPayload qr_payload;
            qr_payload.id = od_id_;
            qr_payload.pk_nd = od_pk_nd_;
            qr_payload.conn_info = conn_info.toStdString();
            qr_payload.expiry = od_expiry_;

            auto qr_data = serializeQR(qr_payload);
            renderQRBitmap(qr_data);
            od_sas_label_->setText(formatSAS(od_sas_code_));

            session_duration_ms_ =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::seconds(auth::sync::kSessionExpirySeconds)).count();
            session_elapsed_.start();
            expiry_timer_->start();
            updateSessionCountdown();
            switchScreen(WaitingQR);
            updateStatus("Waiting for the new device to scan");
        } catch (const std::exception& e) {
            showError(QString("Could not generate the pairing code: %1").arg(e.what()));
        }
    } else {
        onScanQRClicked();
    }
}

void QRSyncTab::onCancelClicked() {
    wipeSession();
    switchScreen(Role);
    updateStatus("Cancelled");
}

void QRSyncTab::onRefreshQRClicked() {
    if (!od_mode_) return;
    try {
        if (RAND_bytes(od_id_.data(), static_cast<int>(od_id_.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed for session ID");
        }
        od_expiry_ = std::chrono::system_clock::now() +
                     std::chrono::seconds(auth::sync::kSessionExpirySeconds);

        od_session_.id = od_id_;
        od_session_.pk_nd = od_pk_nd_;
        od_session_.sk_nd = sk_nd_;
        od_session_.expiry = od_expiry_;
        od_session_.used = false;

        od_sas_code_ = computeSAS(od_pk_nd_, od_id_);
        od_session_.sas = od_sas_code_;
        od_sas_label_->setText(formatSAS(od_sas_code_));

        quint16 port = static_cast<quint16>(server_->serverPort());
        QString host = reachableLanAddress();
        QString conn_info = QString("%1:%2").arg(host).arg(port);

        auth::sync::QRPayload qr_payload;
        qr_payload.id = od_id_;
        qr_payload.pk_nd = od_pk_nd_;
        qr_payload.conn_info = conn_info.toStdString();
        qr_payload.expiry = od_expiry_;

        auto qr_data = serializeQR(qr_payload);
        renderQRBitmap(qr_data);
        session_duration_ms_ =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::seconds(auth::sync::kSessionExpirySeconds)).count();
        session_elapsed_.start();
        expiry_timer_->start();
        updateSessionCountdown();

        updateStatus("QR refreshed");
    } catch (const std::exception& e) {
        showError(QString("Refresh failed: %1").arg(e.what()));
    }
}

// ---------------------------------------------------------------------------
// Camera / scanning
// ---------------------------------------------------------------------------

void QRSyncTab::onScanQRClicked() {
    if (od_mode_) return;
    qr_decoded_ = false;
    decode_attempts_ = 0;
    preview_elapsed_.invalidate();
    decode_elapsed_.invalidate();
    scanning_label_->setText("Opening camera…");
    switchScreen(Scanning);
    startCameraScanner();
}

void QRSyncTab::startCameraScanner() {
    if (pages_->currentIndex() != static_cast<int>(Scanning) || od_mode_) return;

    QCoreApplication* app = QCoreApplication::instance();
    if (!app) {
        scanning_label_->setText("Camera access is unavailable. Restart the app and try again.");
        updateStatus("Camera unavailable");
        return;
    }

    const QCameraPermission permission;
    const auto permission_status = app->checkPermission(permission);
    if (permission_status == Qt::PermissionStatus::Undetermined) {
        scanning_label_->setText("Allow camera access to scan your old device’s QR code.");
        updateStatus("Requesting camera permission");
        app->requestPermission(permission, this, [this](const QPermission& result) {
            if (pages_->currentIndex() != static_cast<int>(Scanning) || od_mode_) return;
            if (result.status() == Qt::PermissionStatus::Granted) {
                startCameraScanner();
            } else {
                scanning_label_->setText(
                    "Camera permission was denied. Enable camera access in system settings, then try again.");
                updateStatus("Camera permission denied");
            }
        });
        return;
    }
    if (permission_status != Qt::PermissionStatus::Granted) {
        scanning_label_->setText(
            "Camera permission is required. Enable camera access in system settings, then try again.");
        updateStatus("Camera permission denied");
        return;
    }

    const auto cameras = QMediaDevices::videoInputs();
    if (cameras.isEmpty()) {
        has_camera_ = false;
        scanning_label_->setText("No camera was found on this device. Connect or enable a camera, then try again.");
        updateStatus("No camera available");
        return;
    }

    QCameraDevice selected_camera = cameras.front();
    for (const auto& device : cameras) {
        if (device.position() == QCameraDevice::BackFace) {
            selected_camera = device;
            break;
        }
    }

    stopCameraScanner();
    camera_ = new QCamera(selected_camera, this);

    QCameraFormat selected_format;
    int selected_area = 0;
    for (const auto& format : selected_camera.videoFormats()) {
        const QSize resolution = format.resolution();
        const int area = resolution.width() * resolution.height();
        if (area < 640 * 360 || area > 1280 * 720 || format.maxFrameRate() < 15.0f)
            continue;
        if (area > selected_area) {
            selected_area = area;
            selected_format = format;
        }
    }
    if (selected_area > 0) camera_->setCameraFormat(selected_format);
    camera_->setZoomFactor(camera_->minimumZoomFactor());

    capture_session_->setCamera(camera_);
    connect(camera_, &QCamera::errorOccurred, this,
            [this](QCamera::Error, const QString& error) {
                has_camera_ = false;
                if (pages_->currentIndex() != static_cast<int>(Scanning)) return;
                scanning_label_->setText(
                    QString("Could not start the camera: %1. Check camera access in system settings.")
                        .arg(error));
                updateStatus("Camera failed to start");
            });

    has_camera_ = true;
    scanning_label_->setText("Point the camera at the QR code on your old device.");
    updateStatus("Camera ready — scan the pairing QR code");
    preview_elapsed_.start();
    decode_elapsed_.start();
    camera_->start();
}

void QRSyncTab::stopCameraScanner() {
    ++scan_generation_;
    preview_elapsed_.invalidate();
    decode_elapsed_.invalidate();
    if (!camera_) {
        has_camera_ = false;
        return;
    }
    camera_->stop();
    capture_session_->setCamera(nullptr);
    delete camera_;
    camera_ = nullptr;
    has_camera_ = false;
    camera_viewfinder_->clear();
}

void QRSyncTab::processCameraFrame(const QVideoFrame& frame) {
    if (!has_camera_ || od_mode_) return;
    if (pages_->currentIndex() != static_cast<int>(Scanning)) return;

    const bool update_preview = !preview_elapsed_.isValid() ||
                                preview_elapsed_.elapsed() >= 80;
    const bool decode_due = !decode_pending_ &&
                            (!decode_elapsed_.isValid() ||
                             decode_elapsed_.elapsed() >= 150);
    if (!update_preview && !decode_due) return;

    QImage image = frame.toImage();
    if (image.isNull()) return;

    if (update_preview) {
        preview_elapsed_.restart();
        camera_viewfinder_->setPixmap(QPixmap::fromImage(image).scaled(
            camera_viewfinder_->size(), Qt::KeepAspectRatio,
            Qt::FastTransformation));
    }

    if (!decode_due) return;
    decode_elapsed_.restart();
    decode_pending_ = true;
    decode_generation_ = scan_generation_;
    const bool thorough_fallback = (++decode_attempts_ % 5u) == 0u;
    decode_watcher_->setFuture(
        QtConcurrent::run(decodePairingQrImage, std::move(image), thorough_fallback));

}

void QRSyncTab::handleScannedQr(const std::vector<uint8_t>& qr_data) {
    if (od_mode_) return;

    try {
        auto now = std::chrono::system_clock::now();
        qr_payload_ = scanPairingQR(qr_data, now);

        id_ = qr_payload_.id;
        pk_nd_ = qr_payload_.pk_nd;
        expiry_ = qr_payload_.expiry;

        session_.id = id_;
        session_.pk_nd = pk_nd_;
        session_.expiry = expiry_;
        session_.used = false;
        session_duration_ms_ =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                expiry_ - now).count();
        session_elapsed_.start();
        expiry_timer_->start();
        updateSessionCountdown();

        sas_code_ = computeSAS(pk_nd_, id_);
        session_.sas = sas_code_;

        QString conn_info = QString::fromStdString(qr_payload_.conn_info);
        auto parts = conn_info.split(':');
        if (parts.size() != 2) {
            throw std::runtime_error("Invalid connection info in QR");
        }
        QString host = parts[0];
        quint16 port = static_cast<quint16>(parts[1].toUShort());

        switchScreen(Connected);
        updateStatus(QString("Connecting to %1:%2…").arg(host).arg(port));

        createClientSocket();
        socket_->connectToHost(host, port);
        if (!socket_->waitForConnected(5000)) {
            throw std::runtime_error(socket_->errorString().toStdString());
        }

        switchScreen(SAS);
        od_sas_label_->setText(formatSAS(sas_code_));
        updateStatus("Connected");
    } catch (const std::exception& e) {
        showError(QString("QR scan failed: %1").arg(e.what()));
    }
}

// ---------------------------------------------------------------------------
// Socket handling
// ---------------------------------------------------------------------------

void QRSyncTab::handleSocketData() {
    if (!socket_) return;
    socket_rx_.append(socket_->readAll());

    while (socket_rx_.size() >= 4) {
        quint32 len = (static_cast<quint32>(static_cast<uchar>(socket_rx_[0])) << 24) |
                      (static_cast<quint32>(static_cast<uchar>(socket_rx_[1])) << 16) |
                      (static_cast<quint32>(static_cast<uchar>(socket_rx_[2])) << 8) |
                      static_cast<quint32>(static_cast<uchar>(socket_rx_[3]));

        if (socket_rx_.size() < 4 + static_cast<int>(len)) break;

        const char* payload = socket_rx_.constData() + 4;
        quint8 type = static_cast<quint8>(payload[0]);
        QByteArray session_id(payload + 1, 16);
        QByteArray body(payload + 17, static_cast<int>(len) - 17);

        socket_rx_.remove(0, 4 + static_cast<int>(len));
        handleSocketFrame(type, session_id, body);
    }
}

void QRSyncTab::handleSocketFrame(quint8 type, const QByteArray& peer_session_id,
                                  const QByteArray& body) {
    const auto now = std::chrono::system_clock::now();
    if (isSessionExpired()) {
        expireSession();
        return;
    }

    QByteArray my_id = sessionId();
    if (peer_session_id != my_id) {
        showError("Received frame with mismatched session ID");
        return;
    }

    auto verify_fn = [this](const std::vector<uint8_t>& message,
                            const std::vector<uint8_t>& signature,
                            const std::vector<uint8_t>& public_key) -> bool {
        if (!tpm_) return false;
        return tpm_->verify(message, signature, public_key);
    };

    switch (static_cast<int>(type)) {
        case 1: {  // kOdApproval - OD sends, ND receives
            if (od_mode_) {
                showError("Received OdApproval but this is the Old Device");
                return;
            }
            try {
                std::vector<uint8_t> od_approval_bytes(body.begin(), body.end());
                auto od_approval = deserializeOdApproval(od_approval_bytes);

                if (od_approval.id != id_) {
                    showError("OD approval session ID mismatch");
                    return;
                }
                if (now >= od_approval.expiry) {
                    showError("OD approval has expired");
                    return;
                }

                nd_auth_ = acceptOldDeviceApproval(session_, od_approval, now, verify_fn);
                if (!nd_auth_.valid()) {
                    showError("OD approval signature verification failed");
                    return;
                }
                new_device_approved_ = true;
                updateStatus("Old device approved");
                approving_nd_label_->setText(
                    "The old device has approved.\n"
                    "Tap Approve to continue.");
                nd_approve_btn_->setEnabled(true);
                nd_approve_btn_->show();
            } catch (const std::exception& e) {
                showError(QString("OD approval handling failed: %1").arg(e.what()));
            }
            break;
        }

        case 2: {  // kNdApproval - ND sends, OD receives
            if (!od_mode_) {
                showError("Received NdApproval but this is the New Device");
                return;
            }
            try {
                std::vector<uint8_t> nd_approval_bytes(body.begin(), body.end());
                auto nd_approval = deserializeNdApproval(nd_approval_bytes);

                od_auth_ = acceptNewDeviceApproval(od_session_, od_sas_code_,
                                                   nd_approval, verify_fn);
                if (!od_auth_.valid()) {
                    showError("ND approval signature verification failed");
                    return;
                }
                old_device_approved_ = true;
                updateStatus("New device verified");
            } catch (const std::exception& e) {
                showError(QString("ND approval handling failed: %1").arg(e.what()));
            }
            break;
        }

        case 3: {  // kKemCiphertext - OD sends, ND receives
            if (!od_mode_) {
                showError("Received KEM ciphertext but this is the New Device");
                return;
            }
            try {
                if (body.size() != 1088) {
                    showError(QString("Invalid KEM ciphertext length: %1").arg(body.size()));
                    return;
                }
                std::vector<uint8_t> kem_ct(body.begin(), body.end());
                std::array<uint8_t, 32> shared_secret =
                    kemDecapsulate(sk_nd_, kem_ct);
                noise_key_ = std::vector<uint8_t>(shared_secret.begin(),
                                                  shared_secret.end());

                std::vector<uint8_t> serialized =
                    auth::SerializeVault(transfer_entries_);
                std::vector<uint8_t> encrypted =
                    aesGcmEncrypt(noise_key_, serialized);

                sendPlainFrame(5,
                    QByteArray(reinterpret_cast<const char*>(encrypted.data()),
                               static_cast<int>(encrypted.size())));
                switchScreen(Transferring);
                updateStatus("Sending vault…");
            } catch (const std::exception& e) {
                showError(QString("KEM decapsulation failed: %1").arg(e.what()));
            }
            break;
        }

        case 5: {  // kTransfer - OD sends, ND receives
            if (od_mode_) {
                showError("Received vault transfer but this is the Old Device");
                return;
            }
            try {
                std::vector<uint8_t> transfer_bytes(body.begin(), body.end());
                std::vector<uint8_t> plaintext =
                    aesGcmDecrypt(noise_key_, transfer_bytes);
                auto remote_entries = auth::DeserializeVault(plaintext);

                std::vector<auth::VaultEntry> local_entries;
                QString err;
                if (password_manager_) {
                    password_manager_->exportVaultEntriesForSync(local_entries, err);
                }

                auto merged = mergeVaultEntries(local_entries, remote_entries);

                std::vector<auth::sync::DevicePk> trust_list;
                if (!od_pk_od_.empty()) {
                    auth::sync::addTrustedDevice(trust_list, od_pk_od_);
                }

                saveLocalVault(merged);

                sendPlainFrame(6, QByteArray());

                wipeSession();
                switchScreen(Done);
                updateStatus("Vault merged and saved");
                emit syncFinished(true, "Vault sync complete");
            } catch (const std::exception& e) {
                showError(QString("Vault transfer failed: %1").arg(e.what()));
            }
            break;
        }

        case 6: {  // kAck - ND sends, OD receives
            if (!od_mode_) {
                showError("Received Ack but this is the New Device");
                return;
            }
            updateStatus("Vault transfer acknowledged");
            wipeSession();
            switchScreen(Done);
            emit syncFinished(true, "Vault synced successfully");
            break;
        }

        case 255: {  // kAbort
            showError("Peer aborted the sync session");
            break;
        }

        default: {
            showError(QString("Unknown frame type: %1").arg(static_cast<int>(type)));
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// SAS / approval
// ---------------------------------------------------------------------------

void QRSyncTab::onCodesMatchClicked() {
    if (isSessionExpired()) {
        expireSession();
        return;
    }
    updateStatus("Codes match");

    if (od_mode_) {
        od_sas_label_->setText(formatSAS(od_sas_code_));
        switchScreen(ApprovingOD);
        od_approve_btn_->setEnabled(true);
        od_approve_btn_->show();
    } else {
        od_sas_label_->setText(formatSAS(sas_code_));
        switchScreen(ApprovingND);
        nd_approve_btn_->setEnabled(false);
        nd_approve_btn_->hide();
    }
}

void QRSyncTab::onCodesDifferClicked() {
    showError("The codes do not match. Pairing cancelled.");
    wipeSession();
}

void QRSyncTab::onApproveClicked() {
    if (isSessionExpired()) {
        expireSession();
        return;
    }
    if (od_mode_) {
        try {
            if (!tpm_) {
                showError("TPM backend unavailable");
                return;
            }
            tpm_->createKey();
            od_pk_od_ = tpm_->getPubkey();

            std::vector<uint8_t> od_digest =
                oldDeviceApprovalDigest(od_id_, od_expiry_, od_pk_nd_);
            od_sigma_od_ = tpm_->sign(od_digest);

            auth::sync::OdApproval od_approval;
            od_approval.id = od_id_;
            od_approval.expiry = od_expiry_;
            od_approval.pk_nd = od_pk_nd_;
            od_approval.device_public_key = std::move(od_pk_od_);
            od_approval.signature = std::move(od_sigma_od_);

            auto od_wire = serializeOdApproval(od_approval);
            sendPlainFrame(1,
                QByteArray(reinterpret_cast<const char*>(od_wire.data()),
                           static_cast<int>(od_wire.size())));

            old_device_approved_ = true;
            od_approve_btn_->setEnabled(false);
            approving_od_label_->setText(
                "Approval sent.\n"
                "Waiting for the new device…");
            updateStatus("Waiting for the new device to approve");
        } catch (const std::exception& e) {
            showError(QString("OD approval failed: %1").arg(e.what()));
        }
    } else {
        if (!nd_auth_.valid()) {
            showError("Waiting for Old Device to approve first");
            return;
        }
        try {
            if (!tpm_) {
                showError("TPM backend unavailable");
                return;
            }
            tpm_->createKey();
            std::vector<uint8_t> nd_pk = tpm_->getPubkey();

            std::vector<uint8_t> nd_digest =
                newDeviceApprovalDigest(sas_code_, pk_nd_, id_);
            std::vector<uint8_t> nd_sigma = tpm_->sign(nd_digest);

            auth::sync::NdApproval nd_approval;
            nd_approval.device_public_key = std::move(nd_pk);
            nd_approval.signature = std::move(nd_sigma);
            auto nd_wire = serializeNdApproval(nd_approval);
            sendPlainFrame(2,
                QByteArray(reinterpret_cast<const char*>(nd_wire.data()),
                           static_cast<int>(nd_wire.size())));

            auto kem_result = kemEncapsulate(pk_nd_, nd_auth_);
            std::vector<uint8_t> kem_ct = std::move(kem_result.first);
            std::array<uint8_t, 32> shared_secret = kem_result.second;
            noise_key_ = std::vector<uint8_t>(shared_secret.begin(),
                                              shared_secret.end());

            sendPlainFrame(3,
                QByteArray(reinterpret_cast<const char*>(kem_ct.data()),
                           static_cast<int>(kem_ct.size())));

            new_device_approved_ = true;
            nd_approve_btn_->setEnabled(false);
            switchScreen(Transferring);
            updateStatus("Waiting for the vault…");
        } catch (const std::exception& e) {
            showError(QString("ND approval failed: %1").arg(e.what()));
        }
    }
}

void QRSyncTab::onDoneClicked() {
    wipeSession();
    switchScreen(Role);
    updateStatus("Ready");
    emit syncFinished(true, "Vault synced");
}
