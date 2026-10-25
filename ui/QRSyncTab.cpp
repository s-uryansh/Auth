#include "QRSyncTab.h"
#include "PasswordManagerTab.h"
#include "SensitiveData.h"
#include "auth/kem_noise.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QPixmap>
#include <QPainter>
#include <QStandardPaths>
#include <QDir>
#include <QInputDialog>
#include <QGuiApplication>
#include <QClipboard>
#include <QByteArray>
#include <QFrame>
#include <QScrollArea>
#include <QImage>
#include <QLabel>
#include <QCamera>
#include <QCameraDevice>
#include <QCameraFormat>
#include <QCoreApplication>
#include <QMediaCaptureSession>
#include <QMediaDevices>
#include <QPermissions>
#include <QVideoFrame>
#include <QVideoSink>
#include <QNetworkInterface>
#include <QNetworkAddressEntry>
#include <QHostAddress>
#include <QtEndian>
#include <QtConcurrentRun>

#include <openssl/rand.h>
#include <ZXing/ReadBarcode.h>
#include <ZXing/ReaderOptions.h>
#include <ZXing/BitMatrix.h>
#include <ZXing/CharacterSet.h>
#include <ZXing/MultiFormatWriter.h>
#include <array>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace {
constexpr quint8 kHello = 1;
constexpr quint8 kSas = 2;
constexpr quint8 kApproveNew = 3;
constexpr quint8 kTransfer = 5;
constexpr quint8 kAck = 6;
constexpr quint8 kAbort = 255;
constexpr quint32 kMaxFrameBytes = 64u * 1024u * 1024u;

QScrollArea* makeScrollablePage(QWidget* page) {
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setWidget(page);
    return scroll;
}

QByteArray decodePairingQrImage(QImage image, bool thorough_fallback) {
    if (image.isNull())
        return {};

    const QImage luminance = image.convertToFormat(QImage::Format_Grayscale8);
    if (luminance.isNull())
        return {};

    const ZXing::ImageView view(luminance.constBits(), luminance.width(), luminance.height(),
                                ZXing::ImageFormat::Lum, luminance.bytesPerLine());
    auto options = ZXing::ReaderOptions()
                       .setFormats(ZXing::BarcodeFormat::QRCode)
                       .setTryHarder(false)
                       .setTryRotate(true)
                       .setTryInvert(false)
                       .setTryDownscale(false);
    auto barcode = ZXing::ReadBarcode(view, options);
    if (!barcode.isValid() && thorough_fallback) {
        auto fallback_options = ZXing::ReaderOptions()
                                   .setFormats(ZXing::BarcodeFormat::QRCode)
                                   .setTryHarder(true)
                                   .setTryRotate(true)
                                   .setTryInvert(true)
                                   .setTryDownscale(true);
        barcode = ZXing::ReadBarcode(view, fallback_options);
    }
    if (!barcode.isValid())
        return {};

    const auto& bytes = barcode.bytes();
    const QByteArray envelope(reinterpret_cast<const char*>(bytes.data()),
                              static_cast<qsizetype>(bytes.size()));
    constexpr auto kPrefix = "AUTHQR:";
    if (!envelope.startsWith(kPrefix) || envelope.size() <= 7)
        return {};
    return QByteArray::fromBase64(envelope.mid(7), QByteArray::AbortOnBase64DecodingErrors);
}

QHostAddress reachableLanAddress() {
    const auto interfaces = QNetworkInterface::allInterfaces();
    const std::array<QNetworkInterface::InterfaceType, 2> preferred_types = {
        QNetworkInterface::Wifi, QNetworkInterface::Ethernet};
    for (const auto preferred_type : preferred_types) {
        for (const QNetworkInterface& iface : interfaces) {
            if (iface.type() != preferred_type) continue;
            const auto flags = iface.flags();
            if (!(flags & QNetworkInterface::IsUp) ||
                !(flags & QNetworkInterface::IsRunning) ||
                (flags & QNetworkInterface::IsLoopBack))
                continue;
            for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
                const QHostAddress address = entry.ip();
                if (address.protocol() != QAbstractSocket::IPv4Protocol ||
                    address.isLoopback() || address.isLinkLocal())
                    continue;
                const quint32 ipv4 = address.toIPv4Address();
                const bool private_address = (ipv4 >> 24) == 10u ||
                    (ipv4 >> 20) == 0xac1u || (ipv4 >> 16) == 0xc0a8u;
                if (private_address) return address;
            }
        }
    }
    return {};
}
} // namespace

QRSyncTab::QRSyncTab(PasswordManagerTab *passwordManager, QWidget *parent)
    : QWidget(parent),
      timer_(new QTimer(this)),
      tpm_(std::make_unique<auth::sync::SoftwareTpm>()),
      pages_(new QStackedWidget(this)),
      role_page_(new QWidget()),
      setup_page_(new QWidget()),
      waiting_qr_page_(new QWidget()),
      scanning_page_(new QWidget()),
      connected_page_(new QWidget()),
      sas_page_(new QWidget()),
      approving_page_(new QWidget()),
      approving_nd_page_(new QWidget()),
      transferring_page_(new QWidget()),
      done_page_(new QWidget()),
      error_page_(new QWidget()),
      qr_label_(new QLabel()),
      countdown_label_(new QLabel()),
      scanner_status_label_(new QLabel()),
      scanner_countdown_label_(new QLabel()),
      camera_preview_(new QLabel()),
      status_label_(new QLabel()),
      sas_label_(new QLabel()),
      error_label_(new QLabel()),
      refresh_btn_(new QPushButton("Refresh QR")),
      match_btn_(new QPushButton("Codes Match")),
      differ_btn_(new QPushButton("Codes Differ")),
      approve_btn_(new QPushButton("Approve")),
      done_btn_(new QPushButton("Done")),
      transfer_progress_(new QLabel()),
      connected_status_label_(new QLabel()),
      approving_status_label_(new QLabel()),
      approving_nd_status_label_(new QLabel()),
      approving_approve_btn_(new QPushButton("Approve")),
      approving_cancel_btn_(new QPushButton("Cancel")) {
    password_manager_ = passwordManager;

    qr_label_->setAlignment(Qt::AlignCenter);
#ifdef Q_OS_ANDROID
    qr_label_->setFixedSize(280, 280);
#else
    qr_label_->setFixedSize(300, 300);
#endif
    sas_label_->setAlignment(Qt::AlignCenter);
    sas_label_->setStyleSheet("font-size: 48px; font-weight: bold;");

    // Role page - first screen: is this the new device or the old device?
    // The two roles drive the pairing protocol differently, so the user picks
    // here rather than the flow guessing.
    auto *role_layout = new QVBoxLayout(role_page_);
    auto *role_title = new QLabel("Which device is this?");
    role_title->setStyleSheet("font-size: 20px; font-weight: bold;");
    role_layout->addWidget(role_title);
    role_layout->addWidget(new QLabel("Choose whether this device is receiving or sending the vault."));
    auto *role_new_btn = new QPushButton("New Device");
    auto *role_old_btn = new QPushButton("Old Device");
    role_layout->addWidget(role_new_btn);
    role_layout->addWidget(role_old_btn);
    role_layout->addStretch();
    connect(role_new_btn, &QPushButton::clicked, this,
            [this]() { onRoleSelected(true); });
    connect(role_old_btn, &QPushButton::clicked, this,
            [this]() { onRoleSelected(false); });

    // Sender role prepares and displays a short-lived pairing QR.
    auto *setup_layout = new QVBoxLayout(setup_page_);
    auto *setup_title = new QLabel("Share this device's vault");
    setup_title->setStyleSheet("font-size: 20px; font-weight: bold;");
    setup_layout->addWidget(setup_title);
    setup_layout->addWidget(new QLabel("Show the pairing code to the new device"));
    setup_layout->addWidget(new QLabel("Keep both devices near you"));
    start_btn_ = new QPushButton("Start");
    setup_layout->addWidget(start_btn_);
    setup_layout->addStretch();
    connect(start_btn_, &QPushButton::clicked, this, &QRSyncTab::onAddDeviceClicked);

    // Waiting QR page N2/N3 - Shows QR and countdown
    auto *waiting_layout = new QVBoxLayout(waiting_qr_page_);
    waiting_layout->addStretch(1);
    waiting_layout->addWidget(new QLabel("Let the new device scan this pairing code"));
    auto *qr_card = new QFrame(waiting_qr_page_);
    qr_card->setObjectName("pairingQrCard");
#ifdef Q_OS_ANDROID
    qr_card->setFixedSize(300, 300);
#else
    qr_card->setFixedSize(320, 320);
#endif
    qr_card->setStyleSheet("QFrame#pairingQrCard { background: white; border: 1px solid palette(mid); border-radius: 8px; }");
    auto *qr_card_layout = new QVBoxLayout(qr_card);
    qr_card_layout->setContentsMargins(10, 10, 10, 10);
    qr_card_layout->addWidget(qr_label_, 0, Qt::AlignCenter);
    waiting_layout->addWidget(qr_card, 0, Qt::AlignHCenter);
    waiting_layout->addWidget(countdown_label_);
    waiting_layout->addWidget(status_label_);
    auto *waiting_btns = new QHBoxLayout;
    waiting_btns->addWidget(refresh_btn_);
    auto *waiting_cancel_btn = new QPushButton("Cancel");
    waiting_btns->addWidget(waiting_cancel_btn);
    waiting_layout->addLayout(waiting_btns);
    waiting_layout->addStretch(1);
    connect(waiting_cancel_btn, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);

    // Camera scanner used by the selected new-device role.
    auto *scanner_layout = new QVBoxLayout(scanning_page_);
    auto *scanner_title = new QLabel("Scan the pairing QR code");
    scanner_title->setStyleSheet("font-size: 20px; font-weight: bold;");
    scanner_layout->addWidget(scanner_title);
    camera_preview_->setAlignment(Qt::AlignCenter);
    camera_preview_->setMinimumSize(240, 240);
    camera_preview_->setStyleSheet("border: 1px solid palette(mid); padding: 4px;");
    scanner_layout->addWidget(camera_preview_);
    scanner_layout->addWidget(scanner_status_label_);
    scanner_layout->addWidget(scanner_countdown_label_);
    auto *scanner_cancel_btn = new QPushButton("Cancel");
    scanner_layout->addWidget(scanner_cancel_btn);
    connect(scanner_cancel_btn, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);

    // Connected page N4 - Both devices connected, waiting for SAS
    auto *connected_layout = new QVBoxLayout(connected_page_);
    connected_layout->addWidget(new QLabel("Old device connected."));
    connected_layout->addWidget(new QLabel("Compare codes on both screens"));
    connected_layout->addWidget(connected_status_label_);
    connected_layout->addStretch();

    // SAS page V1 - Show SAS codes, confirm match
    auto *sas_layout = new QVBoxLayout(sas_page_);
    sas_layout->addWidget(new QLabel("Compare these codes:"));
    sas_layout->addWidget(sas_label_);
    auto *sas_desc = new QLabel("Does this match your old device?");
    sas_layout->addWidget(sas_desc);
    auto *sas_btns = new QHBoxLayout;
    sas_btns->addWidget(match_btn_);
    sas_btns->addWidget(differ_btn_);
    sas_layout->addLayout(sas_btns);
    auto *sas_cancel_btn = new QPushButton("Cancel");
    sas_layout->addWidget(sas_cancel_btn);
    connect(sas_cancel_btn, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);

    // Approving page A1 - old device grants approval with its TPM key
    auto *approving_layout = new QVBoxLayout(approving_page_);
    approving_layout->addWidget(new QLabel("Waiting for approval on the old device..."));
    approving_layout->addWidget(approving_status_label_);
    approving_layout->addWidget(approving_approve_btn_);
    approving_layout->addWidget(approving_cancel_btn_);

    // Approving page A2 - new device waits while the old device is verified
    auto *approving_nd_layout = new QVBoxLayout(approving_nd_page_);
    approving_nd_layout->addWidget(new QLabel("Confirming approval from the old device..."));
    approving_nd_layout->addWidget(approving_nd_status_label_);
    approving_nd_layout->addWidget(approve_btn_);

    // Transferring page T1/T2 - Vault transfer progress
    auto *transfer_layout = new QVBoxLayout(transferring_page_);
    transfer_layout->addWidget(transfer_progress_);
    auto *transfer_status_label = new QLabel();
    transfer_layout->addWidget(transfer_status_label);
    auto *transfer_cancel_btn = new QPushButton("Cancel");
    transfer_layout->addWidget(transfer_cancel_btn);
    connect(transfer_cancel_btn, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);

    // Done page T3 - Sync complete
    auto *done_layout = new QVBoxLayout(done_page_);
    done_layout->addWidget(new QLabel("Sync complete"));
    auto *done_status_label = new QLabel();
    done_layout->addWidget(done_status_label);
    done_layout->addWidget(done_btn_);

    // Error page
    auto *error_layout = new QVBoxLayout(error_page_);
    error_label_->setStyleSheet("color: red; font-weight: bold; font-size: 14px;");
    error_label_->setWordWrap(true);
    error_layout->addWidget(error_label_);
    auto *error_status_label = new QLabel();
    error_layout->addWidget(error_status_label);
    auto *error_btns = new QHBoxLayout;
    auto *error_done_btn = new QPushButton("Done");
    auto *error_refresh_btn = new QPushButton("New QR");
    error_btns->addWidget(error_refresh_btn);
    error_btns->addWidget(error_done_btn);
    error_layout->addLayout(error_btns);

    // Page order must match the Screen enum ordering used by switchScreen().
    pages_->addWidget(makeScrollablePage(role_page_));       // Screen::Role
    pages_->addWidget(makeScrollablePage(setup_page_));      // Screen::Setup
    pages_->addWidget(makeScrollablePage(waiting_qr_page_)); // Screen::WaitingQR
    pages_->addWidget(makeScrollablePage(scanning_page_));   // Screen::Scanning
    pages_->addWidget(makeScrollablePage(connected_page_));  // Screen::Connected
    pages_->addWidget(makeScrollablePage(sas_page_));        // Screen::SAS
    pages_->addWidget(makeScrollablePage(approving_page_));  // Screen::ApprovingOD
    pages_->addWidget(makeScrollablePage(approving_nd_page_));// Screen::ApprovingND
    pages_->addWidget(makeScrollablePage(transferring_page_));// Screen::Transferring
    pages_->addWidget(makeScrollablePage(done_page_));       // Screen::Done
    pages_->addWidget(makeScrollablePage(error_page_));      // Screen::Error

    auto *main_layout = new QVBoxLayout(this);
    main_layout->addWidget(pages_);

    // Button connections
    connect(refresh_btn_, &QPushButton::clicked, this, &QRSyncTab::onRefreshQRClicked);
    connect(match_btn_, &QPushButton::clicked, this, &QRSyncTab::onCodesMatchClicked);
    connect(differ_btn_, &QPushButton::clicked, this, &QRSyncTab::onCodesDifferClicked);
    connect(approve_btn_, &QPushButton::clicked, this, &QRSyncTab::onApproveClicked);
    connect(done_btn_, &QPushButton::clicked, this, &QRSyncTab::onDoneClicked);
    connect(approving_approve_btn_, &QPushButton::clicked, this, &QRSyncTab::onApproveClicked);
    connect(approving_cancel_btn_, &QPushButton::clicked, this, &QRSyncTab::onCancelClicked);
    connect(error_done_btn, &QPushButton::clicked, this, &QRSyncTab::onDoneClicked);
    connect(error_refresh_btn, &QPushButton::clicked, this, &QRSyncTab::onRefreshQRClicked);

    // Timer for countdown
    connect(timer_, &QTimer::timeout, this, [this]() {
        if (current_screen_ == Screen::WaitingQR || current_screen_ == Screen::Scanning ||
            current_screen_ == Screen::Connected || current_screen_ == Screen::SAS ||
            current_screen_ == Screen::ApprovingOD || current_screen_ == Screen::ApprovingND ||
            current_screen_ == Screen::Transferring) {
            auto now = std::chrono::system_clock::now();
            const auto deadline = od_mode_ ? expiry_ : od_expiry_;
            auto remaining = std::chrono::duration_cast<std::chrono::seconds>(deadline - now).count();
            if (remaining <= 0) {
                wipeSession();
                showError("QR sync session expired. Start again on both devices.");
                switchScreen(Screen::Error);
                return;
            }
            int m = remaining / 60;
            int s = remaining % 60;
            const QString countdown = QString("Session expires in %1:%2").arg(m).arg(s, 2, 10, QChar('0'));
            if (current_screen_ == Screen::Scanning) scanner_countdown_label_->setText(countdown);
            else countdown_label_->setText(countdown);
        }
    });
    timer_->start(1000);

    const QString app_data = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!app_data.isEmpty() && QDir().mkpath(app_data)) {
        store_ = std::make_unique<PasswordVaultFileStore>(app_data + "/password-vault.dat");
    }
    capture_session_ = new QMediaCaptureSession(this);
    sync_server_ = new QTcpServer(this);
    connect(sync_server_, &QTcpServer::newConnection, this, [this]() {
        while (sync_server_->hasPendingConnections()) {
            QTcpSocket* incoming = sync_server_->nextPendingConnection();
            if (sync_socket_) {
                incoming->disconnectFromHost();
                incoming->deleteLater();
                continue;
            }
            sync_socket_ = incoming;
            connect(sync_socket_, &QTcpSocket::readyRead, this, &QRSyncTab::handleSocketData);
            connect(sync_socket_, &QTcpSocket::disconnected, this, [this]() {
                if (current_screen_ != Screen::Done && current_screen_ != Screen::Error)
                    handleNetworkError();
            });
            connect(sync_socket_, &QTcpSocket::errorOccurred, this,
                    [this](QAbstractSocket::SocketError) {
                if (current_screen_ != Screen::Done && current_screen_ != Screen::Error)
                    handleNetworkError();
            });
        }
    });
    video_sink_ = new QVideoSink(this);
    decode_watcher_ = new QFutureWatcher<QByteArray>(this);
    connect(decode_watcher_, &QFutureWatcher<QByteArray>::finished, this, [this]() {
        decode_pending_ = false;
        QByteArray decoded;
        try {
            decoded = decode_watcher_->result();
        } catch (const std::exception&) {
            return;
        }
        if (decode_generation_ != scan_generation_ ||
            current_screen_ != Screen::Scanning || qr_decoded_ || decoded.isEmpty())
            return;
        std::vector<uint8_t> bytes(decoded.begin(), decoded.end());
        handleScannedQr(bytes);
    });
    capture_session_->setVideoOutput(video_sink_);
    connect(video_sink_, &QVideoSink::videoFrameChanged, this,
            [this](const QVideoFrame& frame) { processCameraFrame(frame); });

    switchScreen(Screen::Role);
}

QRSyncTab::~QRSyncTab() {
    wipeSession();
}

void QRSyncTab::switchScreen(Screen s) {
    current_screen_ = s;
    int idx = -1;
    switch (s) {
    case Screen::Role: idx = 0; break;
    case Screen::Setup: idx = 1; break;
    case Screen::WaitingQR: idx = 2; break;
    case Screen::Scanning: idx = 3; break;
    case Screen::Connected: idx = 4; break;
    case Screen::SAS: idx = 5; break;
    case Screen::ApprovingOD: idx = 6; break;
    case Screen::ApprovingND: idx = 7; break;
    case Screen::Transferring: idx = 8; break;
    case Screen::Done: idx = 9; break;
    case Screen::Error: idx = 10; break;
    }
    if (idx >= 0 && idx < pages_->count()) pages_->setCurrentIndex(idx);
}

void QRSyncTab::updateStatus(const QString& text) {
    status_label_->setText(text);
    connected_status_label_->setText(text);
    approving_status_label_->setText(text);
    approving_nd_status_label_->setText(text);
}

void QRSyncTab::showError(const QString& msg) {
    error_label_->setText(msg);
    status_label_->setText("");
}

void QRSyncTab::wipeSession() {
    stopCameraScanner();
    closeTransport();
    qr_decoded_ = false;
    OPENSSL_cleanse(pk_nd_.data(), pk_nd_.size());
    OPENSSL_cleanse(sk_nd_.data(), sk_nd_.size());
    OPENSSL_cleanse(id_.data(), id_.size());
    OPENSSL_cleanse(qr_payload_.pk_nd.data(), qr_payload_.pk_nd.size());
    OPENSSL_cleanse(qr_payload_.id.data(), qr_payload_.id.size());
    sas_code_.clear();
    od_sas_.clear();
    od_qr_bytes_.clear();
    od_pk_n_.fill(0);
    od_sigma_od_.clear();
    od_pk_od_.clear();
    od_expiry_ = std::chrono::system_clock::time_point();
    expiry_ = std::chrono::system_clock::time_point();
    ui::wipeVaultEntries(transfer_entries_);
    transfer_entries_.clear();
    new_device_approved_ = false;
    old_device_approved_ = false;
    if (tpm_) tpm_->wipe();
}

std::string QRSyncTab::formatSAS(const std::string& raw) {
    std::string out;
    for (size_t i = 0; i < raw.size(); ++i) {
        out.push_back(raw[i]);
        if ((i + 1) % 3 == 0 && i + 1 < raw.size()) out.push_back(' ');
    }
    return out;
}

void QRSyncTab::renderQRBitmap(const std::vector<uint8_t>& qrData) {
    try {
        const QByteArray encoded = QByteArray::fromRawData(
            reinterpret_cast<const char*>(qrData.data()), static_cast<qsizetype>(qrData.size())).toBase64();
        const std::string payload("AUTHQR:" + encoded.toStdString());
        auto bitmap = ZXing::MultiFormatWriter(ZXing::BarcodeFormat::QRCode)
                          .setEncoding(ZXing::CharacterSet::BINARY)
                          .setMargin(4)
                          .encode(payload, qr_label_->width(), qr_label_->height());
        const int size = bitmap.width();
        QPixmap pixmap(size, bitmap.height());
        pixmap.fill(Qt::white);
        QPainter painter(&pixmap);
        painter.setPen(Qt::black);
        for (int r = 0; r < bitmap.height(); ++r) {
            for (int c = 0; c < size; ++c) {
                if (bitmap.get(c, r)) painter.drawPoint(c, r);
            }
        }
        qr_label_->setPixmap(pixmap);
    } catch (const std::exception& e) {
        qr_label_->setText("QR render error");
        qWarning("QR render error: %s", e.what());
    }
}

std::vector<auth::VaultEntry> QRSyncTab::loadLocalVault() {
    if (!store_) return {};
    try {
        auto file = store_->load();
        return {}; // Need decryption key which requires master password
    } catch (...) {
        return {};
    }
}

void QRSyncTab::saveLocalVault(const std::vector<auth::VaultEntry>&) {
    // Would need to re-encrypt with current master key
}

void QRSyncTab::onAddDeviceClicked() {
    onStartClicked();
}

void QRSyncTab::closeTransport() {
    if (sync_socket_) {
        sync_socket_->disconnect(this);
        sync_socket_->abort();
        sync_socket_->deleteLater();
        sync_socket_ = nullptr;
    }
    if (sync_server_ && sync_server_->isListening()) sync_server_->close();
    socket_rx_.clear();
}

void QRSyncTab::sendFrame(quint8 type, const QByteArray& body) {
    if (!sync_socket_ || sync_socket_->state() != QAbstractSocket::ConnectedState)
        throw std::runtime_error("Peer connection is not available");
    QByteArray payload;
    payload.reserve(1 + static_cast<qsizetype>(id_.size()) + body.size());
    payload.append(static_cast<char>(type));
    payload.append(reinterpret_cast<const char*>(id_.data()), static_cast<qsizetype>(id_.size()));
    payload.append(body);
    if (static_cast<quint32>(payload.size()) > kMaxFrameBytes)
        throw std::runtime_error("Sync message exceeds the transfer limit");
    const quint32 length = qToBigEndian(static_cast<quint32>(payload.size()));
    QByteArray frame(reinterpret_cast<const char*>(&length), sizeof(length));
    frame += payload;
    if (sync_socket_->write(frame) != frame.size())
        throw std::runtime_error("Could not queue sync message");
}

void QRSyncTab::handleSocketData() {
    if (!sync_socket_) return;
    socket_rx_ += sync_socket_->readAll();
    while (socket_rx_.size() >= 4) {
        quint32 length = 0;
        std::memcpy(&length, socket_rx_.constData(), sizeof(length));
        length = qFromBigEndian(length);
        if (length < 1u + auth::sync::kIdentityBytes || length > kMaxFrameBytes) {
            handleNetworkError();
            return;
        }
        if (static_cast<quint32>(socket_rx_.size() - 4) < length) return;
        const QByteArray payload = socket_rx_.mid(4, static_cast<qsizetype>(length));
        socket_rx_.remove(0, 4 + static_cast<qsizetype>(length));
        if (std::memcmp(payload.constData() + 1, id_.data(), id_.size()) != 0) {
            handleNetworkError();
            return;
        }
        handleSocketFrame(static_cast<quint8>(payload.at(0)), payload.mid(1 + auth::sync::kIdentityBytes));
    }
}

void QRSyncTab::handleSocketFrame(quint8 type, const QByteArray& body) {
    try {
        if (type == kAbort) {
            handleNetworkError();
            return;
        }
        if (od_mode_) {
            if (type == kHello && body.size() == static_cast<qsizetype>(od_pk_n_.size())) {
                std::copy(body.cbegin(), body.cend(), od_pk_n_.begin());
                std::array<uint8_t, 32> transcript{};
                od_sas_ = auth::sync::computeSAS(od_pk_n_, id_, transcript);
                const QByteArray sas(od_sas_.data(), static_cast<qsizetype>(od_sas_.size()));
                sendFrame(kSas, sas);
                approving_status_label_->setText(QString("Compare this code with the new device: %1")
                                                     .arg(QString::fromStdString(formatSAS(od_sas_))));
                switchScreen(Screen::ApprovingOD);
            } else if (type == kApproveNew && body.isEmpty()) {
                new_device_approved_ = true;
                approving_status_label_->setText("New device confirmed the matching code. Approve to transfer the vault.");
                if (old_device_approved_) startTransferIfApproved();
            } else if (type == kAck && body.isEmpty()) {
                switchScreen(Screen::Done);
                emit syncFinished(true, "Vault transferred and saved on the new device");
            } else {
                handleNetworkError();
            }
        } else {
            if (type == kSas && body.size() == 6) {
                const std::string received(body.constData(), static_cast<size_t>(body.size()));
                if (received != sas_code_) {
                    onCodesDifferClicked();
                    return;
                }
                sas_label_->setText(QString::fromStdString(formatSAS(sas_code_)));
                switchScreen(Screen::SAS);
            } else if (type == kTransfer && current_screen_ == Screen::Transferring) {
                vault_data_.assign(body.cbegin(), body.cend());
                auto entries = auth::sync::decryptVaultFromTransfer(vault_data_, sk_nd_);
                QString error;
                if (!password_manager_->importVaultEntriesFromSync(std::move(entries), error)) {
                    showError(error.isEmpty() ? "Could not save the received vault" : error);
                    switchScreen(Screen::Error);
                    emit syncFinished(false, error);
                    return;
                }
                sendFrame(kAck);
                switchScreen(Screen::Done);
                emit syncFinished(true, "Vault received and saved on this device");
            } else {
                handleNetworkError();
            }
        }
    } catch (const std::exception& error) {
        showError(QString::fromUtf8(error.what()));
        switchScreen(Screen::Error);
        emit syncFinished(false, QString::fromUtf8(error.what()));
    }
}

void QRSyncTab::startTransferIfApproved() {
    if (!od_mode_ || !old_device_approved_ || !new_device_approved_ || !sync_socket_) return;
    transfer_progress_->setText("Encrypting and sending vault…");
    switchScreen(Screen::Transferring);
    const auto wire = auth::sync::encryptVaultForTransfer(transfer_entries_, od_pk_n_);
    ui::wipeVaultEntries(transfer_entries_);
    transfer_entries_.clear();
    sendFrame(kTransfer, QByteArray(reinterpret_cast<const char*>(wire.data()),
                                    static_cast<qsizetype>(wire.size())));
}

void QRSyncTab::onStartClicked() {
    try {
        QString vault_error;
        if (!password_manager_ || !password_manager_->exportVaultEntriesForSync(transfer_entries_, vault_error))
            throw std::runtime_error(vault_error.toStdString());
        if (RAND_bytes(id_.data(), id_.size()) != 1) throw std::runtime_error("RAND_bytes ID failed");
        expiry_ = std::chrono::system_clock::now() +
                  std::chrono::seconds(auth::sync::kSessionExpirySeconds);
        if (!sync_server_->listen(QHostAddress::AnyIPv4, 0))
            throw std::runtime_error(("Could not open a local sync connection: " + sync_server_->errorString()).toStdString());
        const QHostAddress lan_address = reachableLanAddress();
        if (lan_address.isNull()) throw std::runtime_error("No reachable IPv4 network address was found");
        qr_payload_.id = id_;
        qr_payload_.pk_nd.fill(0);
        qr_payload_.conn_info = lan_address.toString().toStdString() + ":" +
                                std::to_string(sync_server_->serverPort());
        qr_payload_.expiry = expiry_;
        auto raw = auth::sync::serializeCompactQR(qr_payload_);
        renderQRBitmap(raw);
        updateStatus(QString("Waiting for the new device on %1. Keep both devices on the same reachable network.")
                         .arg(QString::fromStdString(qr_payload_.conn_info)));
        auto now = std::chrono::system_clock::now();
        auto remaining = std::chrono::duration_cast<std::chrono::seconds>(expiry_ - now).count();
        countdown_label_->setText(QString("Expires in %1:%2").arg(remaining/60).arg(remaining%60, 2, 10, QChar('0')));
        switchScreen(Screen::WaitingQR);
        emit syncStarted();
    } catch (const std::exception& e) {
        closeTransport();
        ui::wipeVaultEntries(transfer_entries_);
        transfer_entries_.clear();
        showError(QString::fromStdString(e.what()));
        switchScreen(Screen::Error);
    }
}

void QRSyncTab::onCancelClicked() {
    // Abort and wipe session per failure matrix
    wipeSession();
    switchScreen(Screen::Role);
    emit syncFinished(false, "Pairing cancelled");
}

void QRSyncTab::onRefreshQRClicked() {
    // Regenerate session with new ID and keypair
    wipeSession();
    onStartClicked();
}

void QRSyncTab::onCodesMatchClicked() {
    try {
        if (od_mode_ || !sync_socket_) throw std::runtime_error("No active new-device pairing session");
        sendFrame(kApproveNew);
        new_device_approved_ = true;
        transfer_progress_->setText("Code confirmed. Waiting for old-device approval and encrypted vault transfer…");
        switchScreen(Screen::Transferring);
    } catch (const std::exception& error) {
        showError(QString::fromUtf8(error.what()));
        switchScreen(Screen::Error);
    }
}

void QRSyncTab::onCodesDifferClicked() {
    // Phase E2: SAS codes differ - abort per failure matrix
    showError("Pairing cancelled. Codes did not match. Possible attack.");
    try { if (sync_socket_) sendFrame(kAbort); } catch (...) {}
    wipeSession();
    switchScreen(Screen::Error);
    emit syncFinished(false, "Pairing cancelled: codes did not match");
}

void QRSyncTab::onApproveClicked() {
    try {
        if (!od_mode_ || !sync_socket_ || od_sas_.empty())
            throw std::runtime_error("The old device has not verified the pairing code");
        old_device_approved_ = true;
        approving_status_label_->setText("Old device approved. Waiting for new-device confirmation.");
        startTransferIfApproved();
    } catch (const std::exception& error) {
        showError(QString::fromUtf8(error.what()));
        switchScreen(Screen::Error);
        emit syncFinished(false, QString::fromUtf8(error.what()));
    }
}

void QRSyncTab::onDoneClicked() {
    // Phase H: Final cleanup
    wipeSession();
    switchScreen(Screen::Role);
}

void QRSyncTab::onRoleSelected(bool new_device) {
    // The requested UI has the new device scan. Protocol 4 assigns the QR in
    // the opposite direction; this UI choice is a documented protocol change.
    od_mode_ = !new_device;
    od_expiry_ = std::chrono::system_clock::now() + std::chrono::minutes(5);
    if (new_device) {
        onScanQRClicked();
    } else {
        onStartClicked();
    }
}

void QRSyncTab::onScanQRClicked() {
    preview_timer_.invalidate();
    decode_timer_.invalidate();
    decode_attempts_ = 0;
    ++scan_generation_;
    qr_decoded_ = false;
    scanner_status_label_->setText("Opening camera...");
    scanner_countdown_label_->setText("Session expires in 5:00");
    switchScreen(Screen::Scanning);
    startCameraScanner();
}

void QRSyncTab::startCameraScanner() {
    if (current_screen_ != Screen::Scanning)
        return;
    QCoreApplication* app = QCoreApplication::instance();
    if (!app) {
        handleNoCamera();
        return;
    }

    const QCameraPermission permission;
    const auto status = app->checkPermission(permission);
    if (status == Qt::PermissionStatus::Undetermined) {
        app->requestPermission(permission, this, [this](const QPermission& result) {
            if (current_screen_ == Screen::Scanning &&
                result.status() == Qt::PermissionStatus::Granted)
                startCameraScanner();
            else if (current_screen_ == Screen::Scanning)
                handleNoCamera();
        });
        return;
    }
    if (status != Qt::PermissionStatus::Granted) {
        handleNoCamera();
        return;
    }

    const auto cameras = QMediaDevices::videoInputs();
    if (cameras.isEmpty()) {
        has_camera_ = false;
        handleNoCamera();
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
    if (selected_area > 0)
        camera_->setCameraFormat(selected_format);
    capture_session_->setCamera(camera_);
    connect(camera_, &QCamera::errorOccurred, this,
            [this](QCamera::Error, const QString&) {
                has_camera_ = false;
                handleNoCamera();
            });
    has_camera_ = true;
    camera_->start();
    scanner_status_label_->setText("Point the camera at the pairing QR code.");
}

void QRSyncTab::stopCameraScanner() {
    ++scan_generation_;
    if (!camera_)
        return;
    camera_->stop();
    capture_session_->setCamera(nullptr);
    delete camera_;
    camera_ = nullptr;
    has_camera_ = false;
}

void QRSyncTab::processCameraFrame(const QVideoFrame& frame) {
    if (current_screen_ != Screen::Scanning || qr_decoded_)
        return;

    const bool update_preview = !preview_timer_.isValid() || preview_timer_.elapsed() >= 80;
    const bool decode_due = !decode_pending_ &&
                            (!decode_timer_.isValid() || decode_timer_.elapsed() >= 150);
    if (!update_preview && !decode_due)
        return;

    const QImage image = frame.toImage();
    if (image.isNull())
        return;
    if (update_preview) {
        preview_timer_.restart();
        camera_preview_->setPixmap(QPixmap::fromImage(image).scaled(
            camera_preview_->size(), Qt::KeepAspectRatio, Qt::FastTransformation));
    }

    if (!decode_due)
        return;
    decode_timer_.restart();
    decode_pending_ = true;
    decode_generation_ = scan_generation_;
    const bool thorough_fallback = (++decode_attempts_ % 5u) == 0u;
    decode_watcher_->setFuture(QtConcurrent::run(decodePairingQrImage, image, thorough_fallback));
}

void QRSyncTab::handleScannedQr(const std::vector<uint8_t>& bytes) {
    auth::sync::QRPayload scanned;
    try {
        scanned = auth::sync::deserializeQR(bytes);
    } catch (const std::exception&) {
        handleInvalidQR();
        return;
    }
    if (std::chrono::system_clock::now() >= scanned.expiry) {
        stopCameraScanner();
        handleQRExpired();
        return;
    }

    qr_decoded_ = true;
    od_qr_bytes_ = bytes;
    od_expiry_ = scanned.expiry;
    id_ = scanned.id;
    stopCameraScanner();
    try {
        OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        if (!kem) throw std::runtime_error("Could not initialize ML-KEM-768");
        const bool generated = OQS_KEM_keypair(kem, pk_nd_.data(), sk_nd_.data()) == OQS_SUCCESS;
        OQS_KEM_free(kem);
        if (!generated) throw std::runtime_error("Could not create the new-device transfer key");
        std::array<uint8_t, 32> transcript{};
        sas_code_ = auth::sync::computeSAS(pk_nd_, id_, transcript);

        const QString endpoint = QString::fromStdString(scanned.conn_info);
        const qsizetype colon = endpoint.lastIndexOf(':');
        bool port_ok = false;
        const uint port = colon >= 0 ? endpoint.mid(colon + 1).toUInt(&port_ok) : 0;
        const QHostAddress host(colon >= 0 ? endpoint.left(colon) : QString());
        if (!port_ok || port == 0 || port > 65535 || host.isNull() ||
            host.protocol() != QAbstractSocket::IPv4Protocol)
            throw std::runtime_error("The QR code has an invalid network address");

        sync_socket_ = new QTcpSocket(this);
        connect(sync_socket_, &QTcpSocket::readyRead, this, &QRSyncTab::handleSocketData);
        connect(sync_socket_, &QTcpSocket::connected, this, [this]() {
            try {
                sendFrame(kHello, QByteArray(reinterpret_cast<const char*>(pk_nd_.data()),
                                             static_cast<qsizetype>(pk_nd_.size())));
                connected_status_label_->setText("Connected. Waiting for the comparison code…");
                switchScreen(Screen::Connected);
            } catch (const std::exception& error) {
                showError(QString::fromUtf8(error.what()));
                switchScreen(Screen::Error);
            }
        });
        connect(sync_socket_, &QTcpSocket::errorOccurred, this,
                [this](QAbstractSocket::SocketError) {
            if (current_screen_ != Screen::Done && current_screen_ != Screen::Error)
                handleNetworkError();
        });
        expiry_ = scanned.expiry;
        scanner_status_label_->setText("Connecting to the old device…");
        sync_socket_->connectToHost(host, static_cast<quint16>(port));
    } catch (const std::exception& error) {
        closeTransport();
        showError(QString::fromUtf8(error.what()));
        switchScreen(Screen::Error);
        emit syncFinished(false, QString::fromUtf8(error.what()));
    }
}

void QRSyncTab::decodeError(const QString& message) {
    scanner_status_label_->setText(message);
}

// Edge case handlers from Sec 6
void QRSyncTab::handleQRExpired() {
    showError("QR expired. Ask new device to refresh.");
    switchScreen(Screen::Error);
    emit syncFinished(false, "QR expired");
}

void QRSyncTab::handleNoCamera() {
    stopCameraScanner();
    showError("Camera unavailable or permission denied. Enable camera access in system settings and try again.");
    switchScreen(Screen::Error);
}

void QRSyncTab::handleNetworkError() {
    showError("The device connection was lost or blocked. Keep both devices on the same reachable Wi-Fi network and try again.");
    closeTransport();
    switchScreen(Screen::Error);
    emit syncFinished(false, error_label_->text());
}

void QRSyncTab::handleSessionReuse() {
    showError("Session already used. Start a new pairing.");
    switchScreen(Screen::Error);
}

void QRSyncTab::handleVaultLocked() {
    showError("Vault locked. Unlock to continue.");
    switchScreen(Screen::Error);
}

void QRSyncTab::handleSelfPair() {
    showError("Cannot pair a device with itself.");
    switchScreen(Screen::Error);
}

void QRSyncTab::handleInvalidQR() {
    scanner_status_label_->setText("This is not a vault pairing code. Keep the camera open and try another code.");
}

void QRSyncTab::handleKnownDevice() {
    QMessageBox::information(this, "Known Device", "Known device recognised. Still requires code check and approval.");
}

void QRSyncTab::handleTooManyAttempts() {
    showError("Too many attempts. Wait 5 minutes.");
    switchScreen(Screen::Error);
}

void QRSyncTab::handleNoTPM() {
    QMessageBox::warning(this, "No Secure Chip",
                         "This device has no secure chip. Pairing uses code check + approval only.");
}
