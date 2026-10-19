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

static QString registrationPasswordError(const QString &password) {
    const QVector<uint> code_points = password.toUcs4();
    if (code_points.size() < 8) {
        return "Password must be at least 8 characters long";
    }

    bool has_uppercase = false;
    bool has_lowercase = false;
    bool has_digit = false;
    bool has_special = false;

    for (uint code_point : code_points) {
        has_uppercase = has_uppercase || (code_point >= 'A' && code_point <= 'Z');
        has_lowercase = has_lowercase || (code_point >= 'a' && code_point <= 'z');
        has_digit = has_digit || (code_point >= '0' && code_point <= '9');
        has_special = has_special ||
            (code_point >= 0x21 && code_point <= 0x7E &&
             !(code_point >= 'A' && code_point <= 'Z') &&
             !(code_point >= 'a' && code_point <= 'z') &&
             !(code_point >= '0' && code_point <= '9'));
    }

    if (!has_uppercase || !has_lowercase || !has_digit || !has_special) {
        return "Password must include an uppercase letter, a lowercase letter, "
               "a number, and a special character";
    }

    return {};
}

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

    const std::string username = user.toStdString();
    if (server_db_.find(username) != server_db_.end()) {
        QMessageBox::warning(this, "Registration Error",
                             "That username is already registered");
        status_label_->setText("Registration failed: username already exists");
        return;
    }

    const QString policy_error = registrationPasswordError(pass);
    if (!policy_error.isEmpty()) {
        QMessageBox::warning(this, "Password Requirements", policy_error);
        status_label_->setText("Registration failed: password requirements");
        return;
    }

    try {
        std::vector<uint8_t> server_r = generateNonce();
        std::vector<uint8_t> pw = secureInput(pass);

        auth::RegistrationPayload payload =
            auth::RegisterUser(username, pw, server_r, user_db_);
        server_db_.emplace(username, std::move(payload));

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
            emit authenticationSucceeded();
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
