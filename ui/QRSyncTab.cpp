#include "QRSyncTab.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGroupBox>
#include <QFormLayout>
#include <QTextEdit>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>

#include <oqs/kem.h>

#include <auth/server_keys.hpp>
#include <auth/kem_utils.hpp>

QRSyncTab::QRSyncTab(QWidget *parent) : QWidget(parent) {
    odUnlocked_ = false;

    auto *mainLayout = new QHBoxLayout(this);

    // === New Device (Left) ===
    auto *ndGroup = new QGroupBox("New Device (ND)", this);
    auto *ndLayout = new QVBoxLayout(ndGroup);

    auto *ndInfoLayout = new QFormLayout();
    sessionIdEdit_ = new QLineEdit(this);
    sessionIdEdit_->setPlaceholderText("Session ID (auto-generate)");
    connInfoEdit_ = new QLineEdit(this);
    connInfoEdit_->setPlaceholderText("Connection info (IP:port or UDP addr)");
    expiryEdit_ = new QLineEdit(this);
    expiryEdit_->setPlaceholderText("Expiry (seconds from now, e.g. 300)");

    ndInfoLayout->addRow("Session ID:", sessionIdEdit_);
    ndInfoLayout->addRow("Conn Info:", connInfoEdit_);
    ndInfoLayout->addRow("Expiry (s):", expiryEdit_);

    generateKeysBtn_ = new QPushButton("Generate ML-KEM-768 Key Pair", this);
    connect(generateKeysBtn_, &QPushButton::clicked, this,
            &QRSyncTab::onGenerateKeysClicked);

    qrCodeDisplay_ = new QLabel("QR code will appear here", this);
    qrCodeDisplay_->setAlignment(Qt::AlignCenter);
    qrCodeDisplay_->setMinimumHeight(100);
    qrCodeDisplay_->setStyleSheet("background: #f0f0f0; border: 1px solid #aaa;");

    ndLayout->addLayout(ndInfoLayout);
    ndLayout->addWidget(generateKeysBtn_);
    ndLayout->addWidget(qrCodeDisplay_);
    mainLayout->addWidget(ndGroup);

    // === Old Device (Right) ===
    auto *odGroup = new QGroupBox("Old Device (OD)", this);
    auto *odLayout = new QVBoxLayout(odGroup);

    auto *odInfoLayout = new QFormLayout();
    odUnlocked_ = false;

    scanQrBtn_ = new QPushButton("Scan QR Code", this);
    connect(scanQrBtn_, &QPushButton::clicked, this,
            &QRSyncTab::onScanQrClicked);

    sasDisplay_ = new QLabel("SAS will appear here after handshake", this);
    sasDisplay_->setAlignment(Qt::AlignCenter);
    sasDisplay_->setMinimumHeight(50);
    sasDisplay_->setStyleSheet("background: #fff; border: 1px solid #ccc;");

    approveBtn_ = new QPushButton("Approve (PIN/Biometric)", this);
    approveBtn_->setEnabled(false);
    connect(approveBtn_, &QPushButton::clicked, this,
            &QRSyncTab::onApproveClicked);

    verdict_ = new QLabel("", this);
    verdict_->setAlignment(Qt::AlignCenter);

    odInfoLayout->addWidget(scanQrBtn_);
    odInfoLayout->addWidget(sasDisplay_);
    odInfoLayout->addWidget(approveBtn_);
    odInfoLayout->addWidget(verdict_);

    odLayout->addLayout(odInfoLayout);
    mainLayout->addWidget(odGroup);

    // === Log/Status ===
    auto *logGroup = new QGroupBox("Log", this);
    auto *logLayout = new QVBoxLayout(logGroup);
    QTextEdit *logView = new QTextEdit(this);
    logView->setReadOnly(true);
    
    logLayout->addWidget(logView);

    // Simple log helper
    auto logMsg = [&](const QString &msg) {
        logView->append(msg);
        qDebug() << "QRSync:" << msg;
    };

    // We'll store a reference for logging via the private log method
    Q_UNUSED(logMsg);

    log("QR Sync UI ready. Click 'Generate Keys' on New Device to start.");
}

QRSyncTab::~QRSyncTab() = default;

void QRSyncTab::log(const QString &msg) {
    Q_UNUSED(msg);
}

// ---- Step 1: New Device generates ML-KEM-768 key pair ----
void QRSyncTab::onGenerateKeysClicked() {
    QString sessionId = sessionIdEdit_->text().trimmed();
    if (sessionId.isEmpty()) {
        sessionId = QString("sess_%1").arg(QDateTime::currentSecsSinceEpoch());
    }
    sessionIdEdit_->setText(sessionId);

    QString connInfo = connInfoEdit_->text().trimmed();
    if (connInfo.isEmpty()) {
        connInfo = "UDP://[::1]:9000";
    }
    connInfoEdit_->setText(connInfo);

    QString expiryText = expiryEdit_->text().trimmed();
    int expirySecs = 300;
    if (!expiryText.isEmpty()) {
        bool ok;
        expirySecs = expiryText.toInt(&ok);
        if (!ok || expirySecs <= 0) expirySecs = 300;
    }

    // Display "QR code" with protocol information (simulated).
    // Actual ML-KEM-768 key pair generation uses liboqs: OQS_KEM_keypair().
    QString qrText = QString("ML-KEM-768 PROTOCOL FLOW (simulated)\n\n"
                             "SessionID: %1\n"
                             "ConnInfo: %2\n"
                             "Expiry: %3s\n"
                             "Step 1: ND generates ML-KEM-768 key pair (P_K^N, S_K^N)\n"
                             "Step 2: ND shows QR code with SessionID & ConnInfo\n"
                             "Step 3: OD scans QR code\n"
                             "Step 4: Noise NK handshake between devices\n"
                             "Step 5: SAS comparison on both screens\n"
                             "Step 6: User approval on OD (PIN/biometric)\n"
                             "Step 7: TPM mutual signatures & vault transfer")
                         .arg(sessionId)
                         .arg(connInfo)
                         .arg(expirySecs);

    qrCodeDisplay_->setText(QString("QR CODE (simulated):\n\n%1").arg(qrText));
    log("Protocol flow displayed. Show the QR code on screen; old device will scan it.");
}

// ---- Step 2: Old Device "scans" QR (simulated) ----
void QRSyncTab::onScanQrClicked() {
    QString qrText = qrCodeDisplay_->text();
    if (qrText.contains("QR CODE (simulated)")) {
        // Extract session ID from the displayed QR text
        QStringList lines = qrText.split('\n');
        QString sid;
        for (int i = 1; i < lines.size(); ++i) {
            QString line = lines[i];
            if (line.startsWith("SessionID:")) {
                sid = line.mid(11).trimmed();
            }
        }

        if (!sid.isEmpty()) {
            // Display SAS for comparison
            QString sas = QString("SAS: session_%1@%2").arg(sid).arg(sid);
            displaySas(sas);

            // Enable approve button; in real flow, user would compare SAS on both screens
            approveBtn_->setEnabled(true);
            verdict_->setText("<i>Scan successful. Compare SAS on both screens.</i>");
            verdict_->setStyleSheet("color: black;");
            log("QR scanned successfully. SAS displayed for comparison.");
        } else {
            QMessageBox::warning(this, "QR Scan Error",
                                 "Could not parse QR code data. "
                                 "Please generate keys first.");
        }
    } else {
        QMessageBox::information(this, "No QR Code",
                                 "Generate ML-KEM keys first so a QR code is available.");
    }
}

// ---- Step 3: Display SAS (Shared Secret Authenticator) ----
void QRSyncTab::displaySas(const QString &sas) {
    sasDisplay_->setText(sas);
    verdict_->setText("<i>Compare this SAS on the New Device screen with the one shown.</i>");
    verdict_->setStyleSheet("color: #666;");
}

// ---- Step 4: User approves on Old Device ----
void QRSyncTab::onApproveClicked() {
    QString sas = sasDisplay_->text();
    if (sas.isEmpty()) {
        QMessageBox::information(this, "No SAS", "No SAS has been generated yet. "
                                                 "Please scan the QR code first.");
        return;
    }

    // Simulate: user has compared SAS on both screens and approved
    approveBtn_->setEnabled(false);
    verdict_->setText("<b>✓ Approved.</b>");
    verdict_->setStyleSheet("color: green;");
    odUnlocked_ = true;

    log("User approved on Old Device. Session keys may now be derived.");

    // Simulate vault sync transfer
    QMessageBox::information(this, "Vault Sync",
                             "Simulating vault transfer from Old Device to New Device...\n\n"
                             "1. OD encapsulates vault under ND's ML-KEM public key\n"
                             "2. ND decrypts and merges entries\n"
                             "3. Both devices update trusted-device lists\n\n"
                             "(Note: Full Protocol 4 implementation requires TPM-backed "
                             "signatures and is a future enhancement.)");
}

// ---- Step 5: Sync Vault (placeholder) ----
void QRSyncTab::onSyncVaultClicked() {
    if (!odUnlocked_) {
        QMessageBox::warning(this, "Not Approved",
                             "Please approve the session on the Old Device first "
                             "(click 'Approve' after SAS comparison).");
        return;
    }

    QMessageBox::information(this, "Vault Sync Complete",
                             "Simulated vault sync complete.\n\n"
                             "• Old device exported vault encrypted under ML-KEM-768 key\n"
                             "• New device decrypted and merged entries\n"
                             "• Trusted-device list updated with peer's TPM public key\n"
                             "• Both devices now share the same vault state\n\n"
                             "Full end-to-end Protocol 4 requires TPM hardware and "
                             "is planned for a future release.");
}