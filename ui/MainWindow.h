#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QWidget>

class AuthTab;
class PasswordManagerTab;
class QRSyncTab;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private:
    QTabWidget *tabs_;
    AuthTab *auth_tab_;
    PasswordManagerTab *pm_tab_;
    QRSyncTab *qr_tab_;
};