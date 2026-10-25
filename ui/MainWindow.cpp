#include "MainWindow.h"
#include "AuthTab.h"
#include "PasswordManagerTab.h"
#include "QRSyncTab.h"

#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("TMPS Auth");
#ifndef Q_OS_ANDROID
    resize(520, 420);
#endif

    tabs_ = new QTabWidget(this);

    auth_tab_ = new AuthTab(this);
    pm_tab_ = new PasswordManagerTab(this);
    qr_tab_ = new QRSyncTab(pm_tab_, this);

    tabs_->addTab(auth_tab_, "Auth");
    tabs_->addTab(pm_tab_, "Password Manager");
    tabs_->addTab(qr_tab_, "QR Sync");
    tabs_->setTabVisible(1, false);
    tabs_->setTabVisible(2, false);

    connect(auth_tab_, &AuthTab::authenticationSucceeded, this, [this]() {
        tabs_->setTabVisible(1, true);
        tabs_->setTabVisible(2, true);
    });

    // Initially hide QR Sync tab until auth is completed
    tabs_->setTabVisible(2, false);

    setCentralWidget(tabs_);
}

MainWindow::~MainWindow() = default;
