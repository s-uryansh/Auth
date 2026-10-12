#include "AuthTab.h"
#include "auth/Authentication.hpp"
#include "auth/Registration.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QMessageBox>

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <stdexcept>

static std::vector<uint8_t> secureInput(const QString &text) {
    std::string s = text.toStdString();
    std::vector<uint8_t> v(s.begin(), s.end());
    OPENSSL_cleanse(&s[0], s.size());
    return v;
}

static std::vector<uint8_t> generateNonce(size_t bytes = 16) {
    std::vector<uint8_t> r(bytes);
    if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
        throw std::runtime_error("CSPRNG failed");
    return r;
}

AuthTab::AuthTab(QWidget *parent) : QWidget(parent) {
    auto *layout = new QVBoxLayout(this);

    auto *form = new QFormLayout;
    username_input_ = new QLineEdit(this);
    password_input_ = new QLineEdit(this);
    password_input_->setEchoMode(QLineEdit::Password);
    form->addRow("Username:", username_input_);
    form->addRow("Password:", password_input_);
    layout->addLayout(form);

    auto *btn_row = new QHBoxLayout;
    register_btn_ = new QPushButton("Register", this);
    login_btn_ = new QPushButton("Login", this);
    btn_row->addWidget(register_btn_);
    btn_row->addWidget(login_btn_);
    layout->addLayout(btn_row);

    status_label_ = new QLabel("Ready", this);
    layout->addWidget(status_label_);

    auto *log_group = new QGroupBox("Log", this);
    auto *log_layout = new QVBoxLayout(log_group);
    log_view_ = new QPlainTextEdit(this);
    log_view_->setReadOnly(true);
    log_view_->setMaximumBlockCount(200);
    log_layout->addWidget(log_view_);
    layout->addWidget(log_group);

    connect(register_btn_, &QPushButton::clicked, this, &AuthTab::onRegisterClicked);
    connect(login_btn_, &QPushButton::clicked, this, &AuthTab::onLoginClicked);
}

AuthTab::~AuthTab() = default;

void AuthTab::log(const QString &msg) {
    log_view_->appendPlainText(msg);
}

void AuthTab::onRegisterClicked() {
    QString user = username_input_->text();
    QString pass = password_input_->text();

    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Username and password required");
        return;
    }

    try {
        std::vector<uint8_t> server_r = generateNonce();
        std::vector<uint8_t> pw = secureInput(pass);

        server_db_[user.toStdString()] =
            auth::RegisterUser(user.toStdString(), pw, server_r, user_db_);

        log("Registered: " + user);
        status_label_->setText("Registered: " + user);
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Error", e.what());
        status_label_->setText("Registration failed");
    }

    password_input_->clear();
}

void AuthTab::onLoginClicked() {
    QString user = username_input_->text();
    QString pass = password_input_->text();

    if (user.isEmpty() || pass.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Username and password required");
        return;
    }

    auto it = server_db_.find(user.toStdString());
    if (it == server_db_.end()) {
        QMessageBox::warning(this, "Error", "User not registered");
        return;
    }

    try {
        std::vector<uint8_t> pw = secureInput(pass);
        bool ok = auth::AuthenticateUser(
            user.toStdString(), pw,
            user_db_[user.toStdString()],
            it->second);

        if (ok) {
            log("Login OK: " + user);
            status_label_->setText("Authenticated: " + user);
        } else {
            log("Login failed: " + user);
            status_label_->setText("Rejected: " + user);
        }
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Error", e.what());
        status_label_->setText("Auth error");
    }

    password_input_->clear();
}
