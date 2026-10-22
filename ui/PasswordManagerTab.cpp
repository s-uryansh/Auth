#include "PasswordManagerTab.h"
#include "SensitiveData.h"

#include <QDir>
#include <QDesktopServices>
#include <QClipboard>
#include <QFormLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QStandardPaths>
#include <QStyle>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace {

QString normalizedWebsite(const QString &raw_website) {
    QString value = raw_website.trimmed();
    if (QUrl(value).scheme().isEmpty()) {
        value.prepend("https://");
    }

    const QUrl url(value);
    if (!url.isValid() || url.host().isEmpty() ||
        (url.scheme() != "http" && url.scheme() != "https")) {
        throw std::runtime_error("Enter a valid HTTP or HTTPS website URL");
    }
    return url.toString(QUrl::FullyEncoded);
}

std::vector<uint8_t> deriveKeyFromText(
    const QString &text,
    const std::vector<uint8_t> &salt,
    const auth::Argon2Params &params) {
    std::vector<uint8_t> password = ui::secureInputBytes(text);
    try {
        std::vector<uint8_t> key = auth::DeriveKey(password, salt, params);
        ui::wipeBytes(password);
        return key;
    } catch (...) {
        ui::wipeBytes(password);
        throw;
    }
}

} // namespace

PasswordManagerTab::PasswordManagerTab(QWidget *parent)
    : QWidget(parent),
      pages_(new QStackedWidget(this)),
      setup_page_(new QWidget(pages_)),
      add_page_(new QWidget(pages_)),
      browse_page_(new QWidget(pages_)),
      master_pass_input_(new QLineEdit(setup_page_)),
      website_input_(new QLineEdit(add_page_)),
      username_input_(new QLineEdit(add_page_)),
      credential_password_input_(new QLineEdit(add_page_)),
      setup_btn_(new QPushButton("Set Master Password", setup_page_)),
      add_btn_(new QPushButton("Add Credential", add_page_)),
      show_browse_btn_(new QPushButton("View Saved Passwords", add_page_)),
      show_add_btn_(new QPushButton("Add Credential", browse_page_)),
      search_input_(new QLineEdit(browse_page_)),
      website_list_(new QListWidget(browse_page_)),
      credential_cards_widget_(new QWidget),
      credential_cards_layout_(new QVBoxLayout(credential_cards_widget_)),
      credential_details_(new QScrollArea(browse_page_)),
      browse_placeholder_(new QLabel("Saved websites will appear here.",
                                     browse_page_)),
      status_label_(new QLabel("", this)),
      session_timer_(new QTimer(this)) {
    setWindowTitle("Password Manager");
    master_pass_input_->setEchoMode(QLineEdit::Password);

    auto *setup_layout = new QVBoxLayout(setup_page_);
    auto *setup_form = new QFormLayout;
    setup_form->addRow("Master password:", master_pass_input_);
    setup_layout->addLayout(setup_form);
    setup_layout->addWidget(setup_btn_);
    setup_layout->addStretch();

    auto *add_layout = new QVBoxLayout(add_page_);
    auto *credential_form = new QFormLayout;
    credential_form->addRow("Website URL:", website_input_);
    credential_form->addRow("Username:", username_input_);
    credential_password_input_->setEchoMode(QLineEdit::Password);
    credential_form->addRow("Password:", credential_password_input_);
    add_layout->addLayout(credential_form);
    auto *add_actions = new QHBoxLayout;
    add_actions->addWidget(add_btn_);
    add_actions->addWidget(show_browse_btn_);
    add_layout->addLayout(add_actions);
    add_layout->addStretch();

    auto *browse_layout = new QVBoxLayout(browse_page_);
    browse_layout->addWidget(browse_placeholder_);
    search_input_->setPlaceholderText("Search saved websites");
    browse_layout->addWidget(search_input_);
    website_list_->setMaximumHeight(180);
    browse_layout->addWidget(website_list_);
    credential_cards_layout_->setContentsMargins(0, 0, 0, 0);
    credential_cards_layout_->addStretch();
    credential_details_->setWidgetResizable(true);
    credential_details_->setWidget(credential_cards_widget_);
    browse_layout->addWidget(credential_details_, 1);
    browse_layout->addWidget(show_add_btn_);
    session_timer_->setInterval(1000);

    pages_->addWidget(setup_page_);
    pages_->addWidget(add_page_);
    pages_->addWidget(browse_page_);

    auto *layout = new QVBoxLayout(this);
    layout->addWidget(pages_);
    layout->addWidget(status_label_);

    connect(setup_btn_, &QPushButton::clicked,
            this, &PasswordManagerTab::onSetupClicked);
    connect(add_btn_, &QPushButton::clicked,
            this, &PasswordManagerTab::onAddClicked);
    connect(show_browse_btn_, &QPushButton::clicked,
            this, &PasswordManagerTab::onShowBrowseClicked);
    connect(show_add_btn_, &QPushButton::clicked,
            this, &PasswordManagerTab::onShowAddClicked);
    connect(website_list_, &QListWidget::itemClicked,
            this, &PasswordManagerTab::onWebsiteClicked);
    connect(search_input_, &QLineEdit::textChanged,
            this, &PasswordManagerTab::filterWebsiteList);
    connect(session_timer_, &QTimer::timeout,
            this, &PasswordManagerTab::checkRevealSession);

    const QString app_data =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (app_data.isEmpty() || !QDir().mkpath(app_data)) {
        pages_->setCurrentWidget(setup_page_);
        updateStatus("Could not create the application data directory");
        setup_btn_->setEnabled(false);
        return;
    }

    store_ = std::make_unique<PasswordVaultFileStore>(
        app_data + "/password-vault.dat");
    workflow_ = std::make_unique<PasswordVaultWorkflow>(*store_, protocol_store_);
    if (!store_->exists()) {
        pages_->setCurrentWidget(setup_page_);
        updateStatus("Set a master password to create your vault");
        return;
    }

    try {
        vault_file_ = store_->load();
        vault_available_ = true;
        pages_->setCurrentWidget(browse_page_);
        refreshWebsiteList();
        updateStatus("Vault locked");
    } catch (const std::exception &e) {
        pages_->setCurrentWidget(browse_page_);
        browse_placeholder_->setText("The saved vault could not be read.");
        show_add_btn_->setEnabled(false);
        updateStatus(QString::fromUtf8(e.what()));
    }
}

PasswordManagerTab::~PasswordManagerTab() {
    ui::wipeBytes(active_key_);
    clearEntries();
}

void PasswordManagerTab::updateStatus(const QString &status) {
    status_label_->setText(status);
}

void PasswordManagerTab::clearEntries() {
    ui::wipeVaultEntries(entries_);
}

void PasswordManagerTab::clearCredentialCards() {
    while (QLayoutItem *item = credential_cards_layout_->takeAt(0)) {
        if (QWidget *widget = item->widget()) {
            const auto labels = widget->findChildren<QLabel *>();
            for (QLabel *label : labels) label->clear();
            delete widget;
        }
        delete item;
    }
    credential_cards_layout_->addStretch();
}

void PasswordManagerTab::refreshWebsiteList() {
    website_list_->clear();
    for (const QString &website : vault_file_.websites) {
        website_list_->addItem(website);
    }
    browse_placeholder_->setText(vault_file_.websites.isEmpty()
        ? "No saved websites yet."
        : "Select a website to view its saved credentials.");
    filterWebsiteList(search_input_->text());
}

void PasswordManagerTab::filterWebsiteList(const QString &query) {
    const QString needle = query.trimmed();
    for (int i = 0; i < website_list_->count(); ++i) {
        QListWidgetItem *item = website_list_->item(i);
        item->setHidden(!item->text().contains(needle, Qt::CaseInsensitive));
    }
}

void PasswordManagerTab::onSetupClicked() {
    const QString master = master_pass_input_->text();
    if (master.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Master password required");
        return;
    }

    try {
        PasswordVaultFile vault;
        vault.salt = auth::GenerateSalt();
        vault.params = auth::kDefaultArgon2Params;
        std::vector<uint8_t> key = deriveKeyFromText(master, vault.salt,
                                                     vault.params);
        vault.ciphertext = auth::EncryptVault(
            key, {}, store_->authenticatedData(vault));
        store_->save(vault);

        ui::wipeBytes(active_key_);
        active_key_ = std::move(key);
        vault_file_ = std::move(vault);
        vault_available_ = true;
        refreshWebsiteList();
        master_pass_input_->clear();
        pages_->setCurrentWidget(add_page_);
        updateStatus("Vault created. Add a website credential.");
    } catch (const std::exception &e) {
        master_pass_input_->clear();
        QMessageBox::critical(this, "Vault Setup Failed",
                              QString::fromUtf8(e.what()));
        updateStatus("Vault setup failed");
    }
}

void PasswordManagerTab::onAddClicked() {
    if (!vault_available_ || !store_) {
        QMessageBox::warning(this, "Vault Unavailable",
                             "Set up or unlock the vault first");
        return;
    }

    const QString website = website_input_->text().trimmed();
    const QString username = username_input_->text();
    const QString password_text = credential_password_input_->text();
    if (website.isEmpty() || username.isEmpty() || password_text.isEmpty()) {
        QMessageBox::warning(this, "Input Error",
                             "Website, username, and password are required");
        return;
    }

    QString canonical_website;
    try {
        canonical_website = normalizedWebsite(website);
    } catch (const std::exception &e) {
        QMessageBox::warning(this, "Invalid Website", QString::fromUtf8(e.what()));
        return;
    }

    std::vector<uint8_t> operation_key;
    const std::vector<uint8_t> *key = &active_key_;
    if (active_key_.empty()) {
        bool accepted = false;
        const QString master = QInputDialog::getText(
            this, "Unlock Vault", "Master password:", QLineEdit::Password,
            {}, &accepted);
        if (!accepted) return;
        try {
            operation_key = deriveKeyFromText(master, vault_file_.salt,
                                               vault_file_.params);
            key = &operation_key;
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Vault Unlock Failed",
                                 QString::fromUtf8(e.what()));
            return;
        }
    }

    std::vector<uint8_t> credential_password;
    try {
        credential_password = ui::secureInputBytes(password_text);
        workflow_->saveNewCredential(*key, canonical_website,
                                     username.toStdString(),
                                     credential_password);
        vault_file_ = store_->load();
        if (viewing_unlocked_) {
            std::vector<auth::VaultEntry> refreshed_entries = auth::DecryptVault(
                *key, vault_file_.ciphertext,
                store_->authenticatedData(vault_file_));
            clearEntries();
            entries_ = std::move(refreshed_entries);
        }
        refreshWebsiteList();

        website_input_->clear();
        username_input_->clear();
        credential_password_input_->clear();
        updateStatus("Credential saved for " + canonical_website);
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Could Not Save Credential",
                              QString::fromUtf8(e.what()));
        updateStatus("Credential was not saved");
    }

    ui::wipeBytes(credential_password);
    ui::wipeBytes(operation_key);
}

void PasswordManagerTab::onShowBrowseClicked() {
    refreshWebsiteList();
    pages_->setCurrentWidget(browse_page_);
}

void PasswordManagerTab::onShowAddClicked() {
    pages_->setCurrentWidget(add_page_);
}

bool PasswordManagerTab::unlockForViewing() {
    bool accepted = false;
    const QString master = QInputDialog::getText(
        this, "View Saved Passwords", "Master password:", QLineEdit::Password,
        {}, &accepted);
    if (!accepted) return false;

    std::vector<uint8_t> candidate_key;
    std::vector<auth::VaultEntry> decrypted;
    try {
        vault_file_ = store_->load();
        candidate_key = deriveKeyFromText(master, vault_file_.salt,
                                          vault_file_.params);
        decrypted = workflow_->unlockAndMigrate(candidate_key);
        vault_file_ = store_->load();
        clearEntries();
        entries_ = std::move(decrypted);
        ui::wipeBytes(active_key_);
        active_key_ = std::move(candidate_key);
        viewing_unlocked_ = true;
        session_clock_.start();
        session_timer_->start();
        updateStatus("Vault unlocked for 10 minutes");
        return true;
    } catch (const std::exception &e) {
        ui::wipeBytes(candidate_key);
        ui::wipeVaultEntries(decrypted);
        QMessageBox::warning(this, "Vault Unlock Failed",
                             QString::fromUtf8(e.what()));
        updateStatus("Vault remains locked");
        return false;
    }
}

void PasswordManagerTab::onWebsiteClicked(QListWidgetItem *item) {
    if (item == nullptr) return;

    selected_website_ = item->text();
    if (!viewing_unlocked_ && !unlockForViewing()) return;
    revealWebsiteCredentials(selected_website_);
}

void PasswordManagerTab::revealWebsiteCredentials(const QString &website) {
    clearCredentialCards();
    std::vector<const auth::VaultEntry *> verified_entries;
    for (const auth::VaultEntry &entry : entries_) {
        if (QString::fromStdString(entry.website) != website) continue;
        if (!workflow_->authenticate(entry)) {
            clearCredentialCards();
            updateStatus("Protocol 2 verification failed; credentials remain hidden.");
            return;
        }
        verified_entries.push_back(&entry);
    }

    int visible_entries = 0;

    for (const auth::VaultEntry *entry_pointer : verified_entries) {
        const auth::VaultEntry &entry = *entry_pointer;
        const QString entry_website = QString::fromStdString(entry.website);

        auto *card = new QGroupBox(website, credential_cards_widget_);
        auto *form = new QFormLayout(card);
        auto *username_row = new QWidget(card);
        auto *username_layout = new QHBoxLayout(username_row);
        username_layout->setContentsMargins(0, 0, 0, 0);
        const QString username = QString::fromUtf8(
            entry.username.data(), static_cast<int>(entry.username.size()));
        auto *username_label = new QLabel(username, username_row);
        username_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto *copy_username = new QPushButton("Copy", username_row);
        username_layout->addWidget(username_label, 1);
        username_layout->addWidget(copy_username);
        form->addRow("Username:", username_row);

        auto *password_row = new QWidget(card);
        auto *password_layout = new QHBoxLayout(password_row);
        password_layout->setContentsMargins(0, 0, 0, 0);
        const QString password = QString::fromUtf8(
            reinterpret_cast<const char *>(entry.password.data()),
            static_cast<int>(entry.password.size()));
        auto *password_label = new QLabel(password, password_row);
        password_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto *copy_password = new QPushButton("Copy", password_row);
        password_layout->addWidget(password_label, 1);
        password_layout->addWidget(copy_password);
        form->addRow("Password:", password_row);

        auto *website_row = new QWidget(card);
        auto *website_layout = new QHBoxLayout(website_row);
        website_layout->setContentsMargins(0, 0, 0, 0);
        auto *website_label = new QLabel(website, website_row);
        website_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto *open_website = new QToolButton(website_row);
        open_website->setText(QString::fromUtf8("↗"));
        open_website->setIcon(style()->standardIcon(QStyle::SP_DirLinkIcon));
        open_website->setToolTip("Open website in browser");
        website_layout->addWidget(website_label, 1);
        website_layout->addWidget(open_website);
        form->addRow("Website:", website_row);

        connect(copy_username, &QPushButton::clicked, this,
                [username]() {
                    QGuiApplication::clipboard()->setText(username);
                });
        connect(copy_password, &QPushButton::clicked, this,
                [password]() {
                    QGuiApplication::clipboard()->setText(password);
                });
        connect(open_website, &QToolButton::clicked, this,
                [this, website]() {
                    try {
                        const QUrl url(normalizedWebsite(website));
                        if (!QDesktopServices::openUrl(url)) {
                            QMessageBox::warning(this, "Open Website",
                                                 "Could not open this website");
                        }
                    } catch (const std::exception &e) {
                        QMessageBox::warning(this, "Invalid Website",
                                             QString::fromUtf8(e.what()));
                    }
                });

        credential_cards_layout_->insertWidget(
            credential_cards_layout_->count() - 1, card);
        ++visible_entries;
    }

    if (visible_entries == 0) {
        auto *empty = new QLabel("No credential is saved for this website.",
                                 credential_cards_widget_);
        credential_cards_layout_->insertWidget(
            credential_cards_layout_->count() - 1, empty);
    }
}

void PasswordManagerTab::checkRevealSession() {
    constexpr qint64 kRevealSessionMs = 10 * 60 * 1000;
    if (!viewing_unlocked_ || session_clock_.elapsed() < kRevealSessionMs) {
        return;
    }

    viewing_unlocked_ = false;
    session_timer_->stop();
    clearCredentialCards();
    clearEntries();
    ui::wipeBytes(active_key_);
    updateStatus("Vault locked. Enter the master password to view credentials.");
}
