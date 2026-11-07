#pragma once

#include <QWidget>
#include <QByteArray>
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QVideoFrame>
#include <QTimer>
#include <QString>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"
#include "auth/tpm2.hpp"
#include "auth/server_keys.hpp"
#include "auth/vault.hpp"
#include "PasswordVaultFileStore.h"
#include "PasswordVaultWorkflow.h"

class QLabel;
class QPushButton;
class QStackedWidget;
class QCamera;
class QMediaCaptureSession;
class QVideoSink;
class QTcpServer;
class QTcpSocket;
class QTimer;
class QMessageBox;

class PasswordManagerTab;
class QRSyncTabTestAccess;

// QR Sync dialog implementing Protocol 4 from TMPS_Auth.pdf.
//
// Protocol 4 flow:
//   1. OD (Old Device, vault holder) generates ML-KEM-768 keypair, Session ID,
//      Expiry, ConnInfo — displays QR code.
//   2. ND (New Device, empty vault) scans QR, connects to OD via TCP.
//   3. Both compute SAS = H(PK_n ∥ ID) [full 32-byte SHA-256] and display for
//      out-of-band visual comparison (SAS never sent over network).
//   4. OD user approves → OD signs σOD = Sign(skOD, H(ID′∥T′∥PKn′)) via TPM
//      → sends ID′, T′, PKn′, pkOD, σOD.
//   5. ND verifies σOD via TPM.
//   6. ND signs σND = Sign(skND, H(SAS ∥ PKn ∥ ID)) via TPM → sends pkND, σND.
//   7. OD verifies σND via TPM.
//   8. OD encapsulates: (Ks, Kem) ← ML-KEM-768.Encaps(PKn), encrypts vault
//      with AES-256-GCM under Ks, sends Kem and E_Vtr.
//   9. ND decapsulates Ks ← ML-KEM-768.Decaps(SKn, Kem), decrypts vault,
//      merges entries.
//
// QR direction: OD (vault holder) shows QR, ND (empty vault) scans it.
class QRSyncTab : public QWidget {
    Q_OBJECT

public:
    explicit QRSyncTab(PasswordManagerTab *password_manager,
                       QWidget *parent = nullptr);
    ~QRSyncTab() override;

signals:
    void syncStarted();
    void syncFinished(bool success, const QString &message);
    void deviceRegistered(const QString &device_id);

public slots:
    void onStartClicked();
    void onCancelClicked();
    void onRefreshQRClicked();
    void onCodesMatchClicked();
    void onCodesDifferClicked();
    void onApproveClicked();
    void onDoneClicked();
    void onScanQRClicked();
    void onRoleSelected(bool old_device);

private:
    friend class QRSyncTabTestAccess;

    enum Screen {
        Role,
        Setup,
        WaitingQR,
        Scanning,
        Connected,
        SAS,
        ApprovingOD,
        ApprovingND,
        Transferring,
        Done,
        Error
    };

    void switchScreen(Screen screen);
    void updateStatus(const QString &status);
    void showError(const QString &message);
    void wipeSession();
    void updateSessionCountdown();
    void expireSession();
    bool isSessionExpired() const;
    QString formatSAS(const std::string &sas);
    void renderQRBitmap(const std::vector<uint8_t> &data);
    std::vector<auth::VaultEntry> loadLocalVault();
    void saveLocalVault(const std::vector<auth::VaultEntry> &entries);
    QByteArray sessionId() const;
    void createClientSocket();
    void sendPlainFrame(quint8 type, const QByteArray &payload);
    void handleSocketData();
    void handleSocketFrame(quint8 type, const QByteArray &peer_session_id,
                           const QByteArray &body);
    void startCameraScanner();
    void stopCameraScanner();
    void processCameraFrame(const QVideoFrame &frame);
    void handleScannedQr(const std::vector<uint8_t> &qr_data);

    // New Device state (scanner side)
    auth::sync::QRPayload qr_payload_;
    std::array<uint8_t, 1184> pk_nd_;
    std::array<uint8_t, 2400> sk_nd_;
    std::array<uint8_t, 16> id_;
    std::chrono::system_clock::time_point expiry_;
    std::string sas_code_;
    auth::sync::SessionSecrets session_;
    auth::sync::NdAuthorization nd_auth_;

    // Old Device state (QR display side)
    std::array<uint8_t, 1184> od_pk_nd_;
    std::array<uint8_t, 16> od_id_;
    std::chrono::system_clock::time_point od_expiry_;
    std::string od_sas_code_;
    auth::sync::SessionSecrets od_session_;
    auth::sync::NdAuthorization od_auth_;
    std::vector<uint8_t> od_pk_od_;
    std::vector<uint8_t> od_sigma_od_;

    // Shared state
    std::vector<uint8_t> noise_key_;
    std::unique_ptr<auth::sync::TpmInterface> tpm_;
    PasswordManagerTab *password_manager_ = nullptr;

    // UI widgets
    QStackedWidget *pages_ = nullptr;

    QWidget *role_page_ = nullptr;
    QLabel *role_label_ = nullptr;
    QPushButton *new_device_btn_ = nullptr;
    QPushButton *old_device_btn_ = nullptr;

    QWidget *setup_page_ = nullptr;
    QLabel *setup_label_ = nullptr;
    QPushButton *start_btn_ = nullptr;

    QWidget *waiting_qr_page_ = nullptr;
    QLabel *waiting_qr_label_ = nullptr;
    QLabel *qr_label_ = nullptr;
    QLabel *qr_countdown_label_ = nullptr;
    QPushButton *refresh_qr_btn_ = nullptr;

    QWidget *scanning_page_ = nullptr;
    QLabel *scanning_label_ = nullptr;
    QLabel *scanner_countdown_label_ = nullptr;
    QLabel *camera_viewfinder_ = nullptr;
    QPushButton *scan_qr_btn_ = nullptr;
    QPushButton *scan_cancel_btn_ = nullptr;

    QWidget *connected_page_ = nullptr;
    QLabel *connected_label_ = nullptr;
    QPushButton *connected_cancel_btn_ = nullptr;

    QWidget *sas_page_ = nullptr;
    QLabel *sas_label_ = nullptr;
    QLabel *od_sas_label_ = nullptr;
    QPushButton *codes_match_btn_ = nullptr;
    QPushButton *codes_differ_btn_ = nullptr;
    QPushButton *sas_cancel_btn_ = nullptr;

    QWidget *approving_od_page_ = nullptr;
    QLabel *approving_od_label_ = nullptr;
    QPushButton *od_approve_btn_ = nullptr;
    QPushButton *od_approve_cancel_btn_ = nullptr;

    QWidget *approving_nd_page_ = nullptr;
    QLabel *approving_nd_label_ = nullptr;
    QPushButton *nd_approve_btn_ = nullptr;
    QPushButton *nd_approve_cancel_btn_ = nullptr;

    QWidget *transferring_page_ = nullptr;
    QLabel *transferring_label_ = nullptr;
    QPushButton *transfer_cancel_btn_ = nullptr;

    QWidget *done_page_ = nullptr;
    QLabel *done_label_ = nullptr;
    QPushButton *done_btn_ = nullptr;

    QWidget *error_page_ = nullptr;
    QLabel *error_label_ = nullptr;
    QPushButton *error_retry_btn_ = nullptr;

    QLabel *status_label_ = nullptr;

    QCamera *camera_ = nullptr;
    QMediaCaptureSession *capture_session_ = nullptr;
    QVideoSink *video_sink_ = nullptr;
    QFutureWatcher<QByteArray> *decode_watcher_ = nullptr;
    QTimer *expiry_timer_ = nullptr;
    QElapsedTimer preview_elapsed_;
    QElapsedTimer decode_elapsed_;
    QElapsedTimer session_elapsed_;
    qint64 session_duration_ms_ = 0;
    quint64 scan_generation_ = 0;
    quint64 decode_generation_ = 0;
    unsigned int decode_attempts_ = 0;
    bool decode_pending_ = false;
    bool has_camera_ = false;

    QTcpServer *server_ = nullptr;
    QTcpSocket *socket_ = nullptr;
    QByteArray socket_rx_;
    QByteArray vault_data_;

    bool od_mode_ = false;
    bool new_device_approved_ = false;
    bool old_device_approved_ = false;
    bool qr_decoded_ = false;
    std::vector<auth::VaultEntry> transfer_entries_;
};
