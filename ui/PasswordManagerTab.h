#pragma once

#include <QLabel>
#include <QElapsedTimer>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTimer>
#include <QWidget>

#include <QVBoxLayout>

#include <memory>
#include <vector>

#include "PasswordVaultFileStore.h"
#include "auth/vault.hpp"

class PasswordManagerTab : public QWidget {
    Q_OBJECT

public:
    explicit PasswordManagerTab(QWidget *parent = nullptr);
    ~PasswordManagerTab() override;

private slots:
    void onSetupClicked();
    void onAddClicked();
    void onShowBrowseClicked();
    void onShowAddClicked();
    void onWebsiteClicked(QListWidgetItem *item);
    void checkRevealSession();

private:
    void updateStatus(const QString &status);
    void clearEntries();
    void clearCredentialCards();
    void refreshWebsiteList();
    void filterWebsiteList(const QString &query);
    void revealWebsiteCredentials(const QString &website);
    bool unlockForViewing();

    QStackedWidget *pages_;
    QWidget *setup_page_;
    QWidget *add_page_;
    QWidget *browse_page_;

    QLineEdit *master_pass_input_;
    QLineEdit *website_input_;
    QLineEdit *username_input_;
    QLineEdit *credential_password_input_;
    QPushButton *setup_btn_;
    QPushButton *add_btn_;
    QPushButton *show_browse_btn_;
    QPushButton *show_add_btn_;
    QLineEdit *search_input_;
    QListWidget *website_list_;
    QWidget *credential_cards_widget_;
    QVBoxLayout *credential_cards_layout_;
    QScrollArea *credential_details_;
    QLabel *browse_placeholder_;
    QLabel *status_label_;
    QTimer *session_timer_;
    QElapsedTimer session_clock_;
    QString selected_website_;

    std::unique_ptr<PasswordVaultFileStore> store_;
    PasswordVaultFile vault_file_;
    std::vector<uint8_t> active_key_;
    std::vector<auth::VaultEntry> entries_;
    bool vault_available_ = false;
    bool viewing_unlocked_ = false;
};
