#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QGroupBox>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QString>

#include <string>
#include <vector>

#include "auth/vault.hpp"

class PasswordManagerTab : public QWidget {
    Q_OBJECT

public:
    explicit PasswordManagerTab(QWidget *parent = nullptr);
    ~PasswordManagerTab() override;

private slots:
    void onSetupClicked();
    void onAddClicked();
    void onRetrieveClicked();
    void onLockClicked();

private:
    void log(const QString &msg);
    void updateStatus(const QString &status);
    bool isUnlocked() const;

    QLineEdit *master_pass_input_;
    QLineEdit *website_input_;
    QLineEdit *username_input_;
    QPushButton *setup_btn_;
    QPushButton *add_btn_;
    QPushButton *retrieve_btn_;
    QPushButton *lock_btn_;
    QLabel *status_label_;
    QListWidget *entry_list_;
    QPlainTextEdit *log_view_;

    std::vector<uint8_t> salt_;
    auth::Argon2Params params_;
    std::vector<uint8_t> encrypted_vault_;
    std::vector<auth::VaultEntry> entries_;
    bool unlocked_ = false;
    bool vault_exists_ = false;
};
