#include "PasswordManagerTab.h"
#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

#include <QMessageBox>
#include <QInputDialog>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <chrono>

static std::vector<uint8_t> secureInput(const QString &text) {
    std::string s = text.toStdString();
    std::vector<uint8_t> v(s.begin(), s.end());
    OPENSSL_cleanse(&s[0], s.size());
    return v;
}

static std::vector<uint8_t> generateRandom(size_t bytes) {
    std::vector<uint8_t> r(bytes);
    if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
        throw std::runtime_error("CSPRNG failed");
    return r;
}

PasswordManagerTab::PasswordManagerTab(QWidget *parent) : QWidget(parent) {
    auto *layout = new QVBoxLayout(this);

    // Master password section
    auto *master_group = new QGroupBox("Master Password", this);
    auto *master_layout = new QFormLayout(master_group);
    master_pass_input_ = new QLineEdit(this);
    master_pass_input_->setEchoMode(QLineEdit::Password);
    master_layout->addRow("Master:", master_pass_input_);
    layout->addWidget(master_group);

    // Website credential section
    auto *cred_group = new QGroupBox("Credential", this);
    auto *cred_layout = new QFormLayout(cred_group);
    website_input_ = new QLineEdit(this);
    username_input_ = new QLineEdit(this);
    cred_layout->addRow("Website:", website_input_);
    cred_layout->addRow("Username:", username_input_);
    layout->addWidget(cred_group);

    // Buttons
    auto *btn_row = new QHBoxLayout;
    setup_btn_ = new QPushButton("Setup Vault", this);
    add_btn_ = new QPushButton("Add Credential", this);
    retrieve_btn_ = new QPushButton("Retrieve", this);
    lock_btn_ = new QPushButton("Lock", this);
    btn_row->addWidget(setup_btn_);
    btn_row->addWidget(add_btn_);
    btn_row->addWidget(retrieve_btn_);
    btn_row->addWidget(lock_btn_);
    layout->addLayout(btn_row);

    // Status
    status_label_ = new QLabel("No vault", this);
    layout->addWidget(status_label_);

    // Entry list
    auto *list_group = new QGroupBox("Stored Credentials", this);
    auto *list_layout = new QVBoxLayout(list_group);
    entry_list_ = new QListWidget(this);
    list_layout->addWidget(entry_list_);
    layout->addWidget(list_group);

    // Log
    auto *log_group = new QGroupBox("Log", this);
    auto *log_layout = new QVBoxLayout(log_group);
    log_view_ = new QPlainTextEdit(this);
    log_view_->setReadOnly(true);
    log_view_->setMaximumBlockCount(200);
    log_layout->addWidget(log_view_);
    layout->addWidget(log_group);

    connect(setup_btn_, &QPushButton::clicked, this, &PasswordManagerTab::onSetupClicked);
    connect(add_btn_, &QPushButton::clicked, this, &PasswordManagerTab::onAddClicked);
    connect(retrieve_btn_, &QPushButton::clicked, this, &PasswordManagerTab::onRetrieveClicked);
    connect(lock_btn_, &QPushButton::clicked, this, &PasswordManagerTab::onLockClicked);

    add_btn_->setEnabled(false);
    retrieve_btn_->setEnabled(false);
}

PasswordManagerTab::~PasswordManagerTab() = default;

void PasswordManagerTab::log(const QString &msg) {
    log_view_->appendPlainText(msg);
}

void PasswordManagerTab::updateStatus(const QString &status) {
    status_label_->setText(status);
}

bool PasswordManagerTab::isUnlocked() const {
    return unlocked_;
}

void PasswordManagerTab::onSetupClicked() {
    QString master = master_pass_input_->text();
    if (master.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Master password required");
        return;
    }

    try {
        salt_ = auth::GenerateSalt();
        params_ = auth::kDefaultArgon2Params;
        entries_.clear();
        encrypted_vault_ = auth::EncryptVault(
            auth::DeriveKey(secureInput(master), salt_, params_), entries_);

        vault_exists_ = true;
        unlocked_ = true;
        master_pass_input_->clear();

        add_btn_->setEnabled(true);
        retrieve_btn_->setEnabled(true);

        log("Vault created");
        updateStatus("Vault ready (unlocked)");
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Error", e.what());
        updateStatus("Setup failed");
    }
}

void PasswordManagerTab::onAddClicked() {
    if (!isUnlocked()) {
        QMessageBox::warning(this, "Error", "Vault is locked");
        return;
    }

    QString website = website_input_->text();
    QString username = username_input_->text();

    if (website.isEmpty() || username.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Website and username required");
        return;
    }

    try {
        auth::VaultEntry entry;
        entry.website = website.toStdString();
        entry.username = username.toStdString();
        entry.password = generateRandom(16);
        entry.salt = generateRandom(16);

        entries_.push_back(std::move(entry));
        encrypted_vault_ = auth::EncryptVault(
            auth::DeriveKey(secureInput(master_pass_input_->text()), salt_, params_),
            entries_);

        entry_list_->addItem(website + " (" + username + ")");

        website_input_->clear();
        username_input_->clear();

        log("Added: " + website);
        updateStatus("Vault updated (" + QString::number(entries_.size()) + " entries)");
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Error", e.what());
    }
}

void PasswordManagerTab::onRetrieveClicked() {
    if (!isUnlocked()) {
        QMessageBox::warning(this, "Error", "Vault is locked");
        return;
    }

    QString website = website_input_->text();
    if (website.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Website required");
        return;
    }

    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&](const auth::VaultEntry &e) { return e.website == website.toStdString(); });

    if (it == entries_.end()) {
        QMessageBox::information(this, "Not Found", "No entry for " + website);
        return;
    }

    QString pw = QString::fromLatin1(
        reinterpret_cast<const char*>(it->password.data()),
        static_cast<int>(it->password.size()));

    QMessageBox::information(this, "Credential",
        "Website: " + QString::fromStdString(it->website) + "\n" +
        "Username: " + QString::fromStdString(it->username) + "\n" +
        "Password: " + pw);

    log("Retrieved: " + website);
}

void PasswordManagerTab::onLockClicked() {
    OPENSSL_cleanse(salt_.data(), salt_.size());
    OPENSSL_cleanse(encrypted_vault_.data(), encrypted_vault_.size());
    for (auto &e : entries_) {
        OPENSSL_cleanse(e.password.data(), e.password.size());
        OPENSSL_cleanse(e.salt.data(), e.salt.size());
    }
    entries_.clear();
    unlocked_ = false;
    vault_exists_ = false;

    add_btn_->setEnabled(false);
    retrieve_btn_->setEnabled(false);
    entry_list_->clear();

    log("Vault locked");
    updateStatus("Vault locked");
}
