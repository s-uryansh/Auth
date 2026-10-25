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
#include "PasswordVaultWorkflow.h"
#include "auth/WebsiteCredentialAuth.hpp"
#include "auth/vault.hpp"

class PasswordManagerTab : public QWidget {
    Q_OBJECT

public:
    explicit PasswordManagerTab(QWidget *parent = nullptr);
    ~PasswordManagerTab() override;

    bool exportVaultEntriesForSync(std::vector<auth::VaultEntry> &entries,
                                   QString &error);
    bool importVaultEntriesFromSync(std::vector<auth::VaultEntry> entries,
                                    QString &error);

private slots:
    void onSetupClicked();
    void onAddClicked();
    void onShowBrowseClicked();
    void onShowAddClicked();
    void onDeleteVaultClicked();
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
    bool createVaultForSync(QString &error);

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
    QPushButton *delete_vault_btn_;
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
    std::unique_ptr<PasswordVaultWorkflow> workflow_;
    auth::WebsiteCredentialAuthStore protocol_store_;
    PasswordVaultFile vault_file_;
    std::vector<uint8_t> active_key_;
    std::vector<auth::VaultEntry> entries_;
    bool vault_available_ = false;
    bool viewing_unlocked_ = false;
};
