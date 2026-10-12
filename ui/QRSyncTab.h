#pragma once

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QTextEdit>
#include <QString>

#include "auth/vault.hpp"

namespace auth {
class ServerKeys;
}  // namespace auth

class QRSyncTab : public QWidget {
    Q_OBJECT

public:
    explicit QRSyncTab(QWidget *parent = nullptr);
    ~QRSyncTab() override;

private slots:
    void onGenerateKeysClicked();
    void onScanQrClicked();
    void onApproveClicked();
    void onSyncVaultClicked();

private:
    void log(const QString &msg);
    QString generateQrCodeData() const;
    void runHandshake();
    void displaySas(const QString &sas);

    // New device (left side) widgets
    QLabel *newDeviceInfo_;
    QLineEdit *sessionIdEdit_;
    QLineEdit *connInfoEdit_;
    QLineEdit *expiryEdit_;
    QPushButton *generateKeysBtn_;
    QLabel *qrCodeDisplay_;

    // Old device (right side) widgets
    QLabel *oldDeviceInfo_;
    QPushButton *scanQrBtn_;
    QLabel *sasDisplay_;
    QPushButton *approveBtn_;
    QLabel *verdict_;

    // Vault sync state
    bool odUnlocked_;
};
