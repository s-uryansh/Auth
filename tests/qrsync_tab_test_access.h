// Test-only accessors for QRSyncTab (declared as friend in QRSyncTab.h).
// Shared by the camera-flow and Protocol 4 loopback suites.
#pragma once

#include "QRSyncTab.h"

#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"

#include <QHostAddress>
#include <QImage>
#include <QLabel>
#include <QPixmap>
#include <QSize>
#include <QStackedWidget>
#include <QString>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QVideoFrame>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

class QRSyncTabTestAccess {
public:
    // ---- camera / rendering helpers ----
    static QSize updatePreview(QRSyncTab& tab) {
        tab.od_mode_ = false;
        tab.has_camera_ = true;
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::Scanning));
        tab.camera_viewfinder_->resize(320, 240);
        tab.preview_elapsed_.invalidate();
        tab.decode_elapsed_.start();
        QThread::msleep(260);
        QImage frame_image(640, 480, QImage::Format_RGB32);
        frame_image.fill(Qt::white);
        tab.processCameraFrame(QVideoFrame(frame_image));
        return tab.camera_viewfinder_->pixmap(Qt::ReturnByValue).size();
    }

    static bool scheduleQrDecode(QRSyncTab& tab, const QImage& frame) {
        tab.od_mode_ = false;
        tab.has_camera_ = true;
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::Scanning));
        tab.camera_viewfinder_->resize(320, 240);
        tab.preview_elapsed_.invalidate();
        tab.decode_elapsed_.invalidate();
        tab.processCameraFrame(QVideoFrame(frame));
        return tab.decode_pending_;
    }

    static bool decodePending(const QRSyncTab& tab) { return tab.decode_pending_; }
    static bool showingError(const QRSyncTab& tab) {
        return tab.pages_->currentIndex() == static_cast<int>(QRSyncTab::Error);
    }
    static int screenIndex(const QRSyncTab& tab) {
        return tab.pages_->currentIndex();
    }

    static QPixmap renderQr(QRSyncTab& tab, const std::vector<uint8_t>& payload) {
        tab.qr_label_->resize(300, 300);
        tab.renderQRBitmap(payload);
        return tab.qr_label_->pixmap(Qt::ReturnByValue);
    }

    static void scanQr(QRSyncTab& tab, const std::vector<uint8_t>& payload) {
        tab.od_mode_ = false;
        tab.handleScannedQr(payload);
    }

    static bool reachedSasScreen(const QRSyncTab& tab) {
        return tab.pages_->currentIndex() == static_cast<int>(QRSyncTab::SAS);
    }

    // ---- session / signer seams ----
    static void installSigner(QRSyncTab& tab,
                              std::unique_ptr<auth::sync::TpmInterface> signer) {
        tab.tpm_ = std::move(signer);
        tab.device_key_ready_ = true;
    }
    static bool hasDeviceSigner(const QRSyncTab& tab) { return tab.tpm_ != nullptr; }

    static void adoptOldDeviceSession(QRSyncTab& tab,
                                      auth::sync::SessionSecrets secrets) {
        tab.od_mode_ = true;
        tab.od_id_ = secrets.id;
        tab.od_pk_nd_ = secrets.pk_nd;
        tab.sk_nd_ = secrets.sk_nd;
        tab.od_expiry_ = secrets.expiry;
        tab.od_sas_code_ = secrets.sas;
        tab.od_session_ = std::move(secrets);
        tab.od_auth_ = auth::sync::NdAuthorization{};
    }

    static void adoptNewDeviceScan(QRSyncTab& tab, auth::sync::SessionSecrets secrets) {
        tab.od_mode_ = false;
        tab.id_ = secrets.id;
        tab.pk_nd_ = secrets.pk_nd;
        tab.sk_nd_ = secrets.sk_nd;
        tab.expiry_ = secrets.expiry;
        tab.sas_code_ = secrets.sas;
        tab.session_ = std::move(secrets);
        tab.nd_auth_ = auth::sync::NdAuthorization{};
    }

    static void setTransferEntries(QRSyncTab& tab,
                                   std::vector<auth::VaultEntry> entries) {
        tab.transfer_entries_ = std::move(entries);
    }
    static void setNoiseKey(QRSyncTab& tab, std::vector<uint8_t> key) {
        tab.noise_key_ = std::move(key);
    }

    // The tab takes Qt-parented ownership, mirroring createClientSocket().
    static void adoptSocket(QRSyncTab& tab, QTcpSocket* socket) {
        socket->setParent(&tab);
        tab.socket_ = socket;
    }
    static void feedFrame(QRSyncTab& tab, quint8 type, const QByteArray& body) {
        tab.handleSocketFrame(type, tab.sessionId(), body);
    }

    static bool odAuthorizationValid(const QRSyncTab& tab) {
        return tab.od_auth_.valid();
    }
    static bool ndAuthorizationValid(const QRSyncTab& tab) {
        return tab.nd_auth_.valid();
    }
    static std::vector<uint8_t> peerPkOd(const QRSyncTab& tab) {
        return tab.peer_pk_od_;
    }
    static std::vector<uint8_t> peerPkNd(const QRSyncTab& tab) {
        return tab.peer_pk_nd_;
    }
    static bool isOldDeviceMode(const QRSyncTab& tab) { return tab.od_mode_; }

    // ---- expiry-suite helpers ----
    static void setupOldSession(QRSyncTab& tab, std::chrono::seconds remaining) {
        tab.od_mode_ = true;
        tab.od_expiry_ = std::chrono::system_clock::now() + remaining;
        tab.session_duration_ms_ =
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        tab.session_elapsed_.start();
        tab.od_id_.fill(0xA5);
        tab.od_pk_nd_.fill(0xA5);
        tab.qr_label_->setText("Active QR");
        tab.server_->close();
        if (!tab.server_->listen(QHostAddress::LocalHost, 0)) return;
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::WaitingQR));
        tab.expiry_timer_->start();
    }
    static void fireExpiryTimer(QRSyncTab& tab) {
        QMetaObject::invokeMethod(tab.expiry_timer_, "timeout",
                                  Qt::DirectConnection);
    }
    static bool serverListening(const QRSyncTab& tab) {
        return tab.server_->isListening();
    }
    static bool sessionIdCleared(const QRSyncTab& tab) {
        return std::all_of(tab.od_id_.begin(), tab.od_id_.end(),
                           [](uint8_t byte) { return byte == 0; });
    }
    static QString qrLabelText(const QRSyncTab& tab) {
        return tab.qr_label_->text();
    }
};
