#include "AuthTab.h"
#include "MainWindow.h"
#include "PasswordManagerTab.h"

#include <QAction>
#include <QLineEdit>
#include <QTabWidget>
#include <QToolBar>
#include <QToolButton>

#include <gtest/gtest.h>

TEST(AuthTabUiTest, AuthPasswordRemainsMaskedWithoutVisibilityControl) {
    AuthTab tab;
    auto* password = tab.findChild<QLineEdit*>("authPasswordInput");
    auto* visibility = tab.findChild<QToolButton*>("passwordVisibilityToggle");
    ASSERT_NE(password, nullptr);
    EXPECT_EQ(visibility, nullptr);
    EXPECT_EQ(password->echoMode(), QLineEdit::Password);
}

TEST(MainWindowUiTest, NoGlobalHomeActionIsShownAfterAuthentication) {
    MainWindow window;
    auto* tabs = window.findChild<QTabWidget*>();
    auto* auth = window.findChild<AuthTab*>();
    auto* home_toolbar = window.findChild<QToolBar*>("globalNavigationToolbar");
    auto* home_action = window.findChild<QAction*>("homeAction");

    ASSERT_NE(tabs, nullptr);
    ASSERT_NE(auth, nullptr);
    ASSERT_TRUE(QMetaObject::invokeMethod(
        auth, "authenticationSucceeded", Qt::DirectConnection));
    EXPECT_EQ(home_toolbar, nullptr);
    EXPECT_EQ(home_action, nullptr);
}
