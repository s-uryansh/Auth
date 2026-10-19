#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QPlainTextEdit>
#include <QString>

#include <string>
#include <unordered_map>
#include <vector>

#include "auth/Registration.hpp"

class AuthTab : public QWidget {
    Q_OBJECT

public:
    explicit AuthTab(QWidget *parent = nullptr);
    ~AuthTab() override;

signals:
    void authenticationSucceeded();

private slots:
    void onRegisterClicked();
    void onLoginClicked();

private:
    void log(const QString &msg);

    QLineEdit *username_input_;
    QLineEdit *password_input_;
    QPushButton *register_btn_;
    QPushButton *login_btn_;
    QLabel *status_label_;
    QPlainTextEdit *log_view_;

    std::unordered_map<std::string, std::vector<uint8_t>> user_db_;
    std::unordered_map<std::string, auth::RegistrationPayload> server_db_;
};
