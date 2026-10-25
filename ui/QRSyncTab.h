#pragma once
#include <QLabel>
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTimer>
#include <QWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QVideoFrame>
#include <memory>
#include <vector>
#include <array>

#include "auth/vault.hpp"
#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"
#include "auth/server_keys.hpp"
#include "PasswordVaultFileStore.h"
#include "PasswordVaultWorkflow.h"

class QCamera;
class QMediaCaptureSession;
class QVideoSink;
class PasswordManagerTab;

class QRSyncTab : public QWidget {
    Q_OBJECT
public:
    explicit QRSyncTab(PasswordManagerTab *passwordManager, QWidget *parent = nullptr);
    ~QRSyncTab() override;

signals:
    void syncStarted();        // notify other tabs
    void syncFinished(bool success, const QString& message);
    void deviceRegistered(const QString& deviceName);

public slots:
    void onAddDeviceClicked();
    void onStartClicked();
    void onCancelClicked();
    void onRefreshQRClicked();
    void onCodesMatchClicked();
    void onCodesDifferClicked();
    void onApproveClicked();
    void onDoneClicked();
    void onScanQRClicked();
    void onRoleSelected(bool newDevice);

private:
    enum class Screen { Role, Setup, WaitingQR, Scanning, Connected, SAS, ApprovingOD, ApprovingND, Transferring, Done, Error };
    void switchScreen(Screen s);
    void updateStatus(const QString& text);
    void showError(const QString& msg);
    void wipeSession();
    std::string formatSAS(const std::string& raw);
    void renderQRBitmap(const std::vector<uint8_t>& qrData);
    std::vector<auth::VaultEntry> loadLocalVault();
    void saveLocalVault(const std::vector<auth::VaultEntry>& entries);

    // ND state
    Screen current_screen_ = Screen::Setup;
    QTimer* timer_;
    QElapsedTimer session_timer_;
    auth::sync::QRPayload qr_payload_;
    std::array<uint8_t, auth::internal::kMlKem768PkBytes> pk_nd_;
    std::array<uint8_t, auth::internal::kMlKem768SkBytes> sk_nd_;
    std::array<uint8_t, auth::sync::kIdentityBytes> id_;
    std::chrono::system_clock::time_point expiry_;
    std::string sas_code_;
    std::unique_ptr<auth::sync::SoftwareTpm> tpm_;
    std::unique_ptr<PasswordVaultFileStore> store_;
    std::unique_ptr<PasswordVaultWorkflow> workflow_;

    // UI widgets
    QStackedWidget* pages_;
    QWidget* role_page_;
    QWidget* setup_page_;
    QWidget* waiting_qr_page_;
    QWidget* scanning_page_;
    QWidget* connected_page_;
    QWidget* sas_page_;
    QWidget* approving_page_;
    QWidget* approving_nd_page_;
    QWidget* transferring_page_;
    QWidget* done_page_;
    QWidget* error_page_;

    QLabel* qr_label_;
    QLabel* countdown_label_;
    QLabel* scanner_status_label_;
    QLabel* scanner_countdown_label_;
    QLabel* camera_preview_;
    QLabel* status_label_;
    QLabel* sas_label_;
    QLabel* error_label_;
    QPushButton* refresh_btn_;
    QPushButton* match_btn_;
    QPushButton* differ_btn_;
    QPushButton* approve_btn_;
    QPushButton* done_btn_;
    QLabel* transfer_progress_;
    QLabel* connected_status_label_;
    QLabel* approving_status_label_;
    QLabel* approving_nd_status_label_;
    QPushButton* approving_approve_btn_;
    QPushButton* approving_cancel_btn_;
    QPushButton* start_btn_;

    // OD state (populated after scan)
    bool od_mode_ = false; // Old device mode (scanning QR)
    std::string od_sas_; // SAS code from old device
    std::vector<uint8_t> od_qr_bytes_; // Scanned QR data
    std::array<uint8_t, auth::internal::kMlKem768PkBytes> od_pk_n_; // Old device's public key
    std::chrono::system_clock::time_point od_expiry_; // Old device's session expiry
    std::vector<uint8_t> od_sigma_od_; // Old device's TPM signature
    std::vector<uint8_t> od_pk_od_; // Old device's TPM public key
    std::vector<uint8_t> od_ephemeral_; // Old device's ephemeral key for handshake
    bool has_tpm_ = false; // Whether device has TPM
    bool has_camera_ = false; // Whether a camera feed is available for QR scanning
    QCamera* camera_ = nullptr;
    QMediaCaptureSession* capture_session_ = nullptr;
    QVideoSink* video_sink_ = nullptr;
    QFutureWatcher<QByteArray>* decode_watcher_ = nullptr;
    QElapsedTimer preview_timer_;
    QElapsedTimer decode_timer_;
    quint64 scan_generation_ = 0;
    quint64 decode_generation_ = 0;
    unsigned int decode_attempts_ = 0;
    bool decode_pending_ = false;
    PasswordManagerTab* password_manager_ = nullptr;
    QTcpServer* sync_server_ = nullptr;
    QTcpSocket* sync_socket_ = nullptr;
    QByteArray socket_rx_;
    std::vector<auth::VaultEntry> transfer_entries_;
    bool new_device_approved_ = false;
    bool old_device_approved_ = false;
    bool qr_decoded_ = false;
    bool is_known_device_ = false; // Whether device is already trusted
    std::vector<uint8_t> vault_data_; // Buffer for vault transfer data

    // Edge case handlers from Sec 6
    void handleQRExpired();
    void handleNoCamera();
    void handleNetworkError();
    void handleSessionReuse();
    void handleVaultLocked();
    void handleSelfPair();
    void handleInvalidQR();
    void handleKnownDevice();
    void handleTooManyAttempts();
    void handleNoTPM();
    void startCameraScanner();
    void stopCameraScanner();
    void processCameraFrame(const QVideoFrame& frame);
    void handleScannedQr(const std::vector<uint8_t>& bytes);
    void decodeError(const QString& message);
    void handleSocketData();
    void handleSocketFrame(quint8 type, const QByteArray& body);
    void sendFrame(quint8 type, const QByteArray& body = {});
    void startTransferIfApproved();
    void closeTransport();
};
