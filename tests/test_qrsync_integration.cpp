// Protocol 4 loopback tests for the QR Sync UI: every authorization gate
// from TMPS_Auth.pdf (Sections IV-B/IV-C and the Protocol 4 diagram) is
// exercised against the real socket handler, with the platform device
// signer replaced by the test seam (QRSyncTabTestAccess).
#include "qrsync_tab_test_access.h"

#include "PasswordManagerTab.h"
#include "QRSyncTab.h"
#include "auth/ecdsa_wire.hpp"
#include "auth/sync_protocol.hpp"
#include "auth/sync_tpm.hpp"
#include "auth/sync_wire.hpp"

#include <QByteArray>
#include <QHostAddress>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QTcpServer>
#include <QTcpSocket>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <vector>

namespace {

using auth::sync::aesGcmDecryptPayload;
using auth::sync::aesGcmEncryptPayload;
using auth::sync::computeSAS;
using auth::sync::kemEncapsulate;
using auth::sync::NdApproval;
using auth::sync::NdAuthorization;
using auth::sync::newDeviceApprovalDigest;
using auth::sync::OdApproval;
using auth::sync::oldDeviceApprovalDigest;
using auth::sync::serializeNdApproval;
using auth::sync::serializeOdApproval;
using auth::sync::SessionSecrets;
using auth::sync::SoftwareTpm;

constexpr quint8 kFrameOdApproval = 1;
constexpr quint8 kFrameNdApproval = 2;
constexpr quint8 kFrameKem = 3;
constexpr quint8 kFrameVault = 5;
constexpr quint8 kFrameAck = 6;

// Socket pair between the test (simulated peer) and the tab under test.
class WirePeer {
public:
    WirePeer() {
        EXPECT_TRUE(server_.listen(QHostAddress::LocalHost, 0));
        client_.connectToHost(QHostAddress::LocalHost, server_.serverPort());
        EXPECT_TRUE(client_.waitForConnected(2000));
        EXPECT_TRUE(server_.waitForNewConnection(2000));
        // Ownership transfers to the tab via adoptSocket()'s setParent; the
        // QPointer goes null if the tab destroyed it first.
        QTcpSocket* socket = server_.nextPendingConnection();
        tab_socket_ = socket;
        EXPECT_NE(socket, nullptr);
    }

    QTcpSocket* tabSocket() { return tab_socket_.data(); }

    bool readFrame(quint8* type, QByteArray* body, int timeout_ms = 300) {
        while (rx_.size() < 4 || rx_.size() < 4 + static_cast<int>(frameLen())) {
            if (!client_.waitForReadyRead(timeout_ms)) return false;
            rx_.append(client_.readAll());
        }
        *type = static_cast<quint8>(rx_.at(4));
        *body = rx_.mid(21, static_cast<int>(frameLen()) - 17);
        rx_.remove(0, 4 + static_cast<int>(frameLen()));
        return true;
    }

    bool silence(int timeout_ms = 300) {
        if (client_.bytesAvailable() > 0) return false;
        return !client_.waitForReadyRead(timeout_ms) &&
               client_.bytesAvailable() == 0;
    }

private:
    quint32 frameLen() const {
        return (static_cast<quint32>(static_cast<uchar>(rx_[0])) << 24) |
               (static_cast<quint32>(static_cast<uchar>(rx_[1])) << 16) |
               (static_cast<quint32>(static_cast<uchar>(rx_[2])) << 8) |
               static_cast<quint32>(static_cast<uchar>(rx_[3]));
    }

    QTcpServer server_;
    QTcpSocket client_;
    QPointer<QTcpSocket> tab_socket_;
    QByteArray rx_;
};

SessionSecrets makeSession() {
    auto session = auth::sync::beginNewDeviceSession(
        "127.0.0.1:1", std::chrono::system_clock::now(),
        std::chrono::seconds(auth::sync::kSessionExpirySeconds));
    session.secrets.sas = computeSAS(session.secrets.pk_nd, session.secrets.id);
    return session.secrets;
}

NdAuthorization testAuth(const SessionSecrets& s) {
    NdAuthorization a;
    a.session_id = s.id;
    a.pk_nd = s.pk_nd;
    a.valid_ = true;
    return a;
}

auth::VaultEntry sampleEntry(const std::string& website) {
    auth::VaultEntry entry;
    entry.website = website;
    entry.username = "alice";
    entry.password = {0x01, 0x02, 0x03};
    entry.salt.assign(auth::kSaltSize, 0xA5);
    entry.lastModified = std::chrono::system_clock::now();
    return entry;
}

QByteArray odApprovalWire(const SessionSecrets& scanned, SoftwareTpm& od_signer) {
    OdApproval approval;
    approval.id = scanned.id;
    approval.expiry = scanned.expiry;
    approval.pk_nd = scanned.pk_nd;
    approval.device_public_key = od_signer.getPubkey();
    approval.signature = od_signer.sign(
        oldDeviceApprovalDigest(approval.id, approval.expiry, approval.pk_nd));
    const auto wire = serializeOdApproval(approval);
    return QByteArray(reinterpret_cast<const char*>(wire.data()),
                      static_cast<int>(wire.size()));
}

QByteArray ndApprovalWire(const SessionSecrets& od_side, SoftwareTpm& nd_signer) {
    NdApproval approval;
    approval.device_public_key = nd_signer.getPubkey();
    approval.signature = nd_signer.sign(newDeviceApprovalDigest(
        od_side.sas, od_side.pk_nd, od_side.id));
    const auto wire = serializeNdApproval(approval);
    return QByteArray(reinterpret_cast<const char*>(wire.data()),
                      static_cast<int>(wire.size()));
}

void installSigner(QRSyncTab& tab, SoftwareTpm*& exposed) {
    auto signer = std::make_unique<SoftwareTpm>();
    signer->createKey();
    exposed = signer.get();
    QRSyncTabTestAccess::installSigner(tab, std::move(signer));
}

}  // namespace

TEST(QRSyncProtocol4GateTest, OldDeviceRejectsKemBeforeSignatureAndWipesSession) {
    QRSyncTab tab(nullptr);
    SoftwareTpm* nd_signer = nullptr;
    installSigner(tab, nd_signer);
    auto session = makeSession();
    QRSyncTabTestAccess::adoptOldDeviceSession(tab, session);
    QRSyncTabTestAccess::setTransferEntries(tab, {sampleEntry("https://od.test")});
    WirePeer peer;
    QRSyncTabTestAccess::adoptSocket(tab, peer.tabSocket());

    // A KEM ciphertext arriving before sigma_ND was verified must not
    // decapsulate or release anything (Protocol 4: no vault data moves
    // until the peer signature verifies), and the violated session must be
    // wiped rather than left half-live.
    auto encaps = kemEncapsulate(session.pk_nd, testAuth(session));
    const QByteArray kem_ct(reinterpret_cast<const char*>(encaps.first.data()),
                            static_cast<int>(encaps.first.size()));
    ASSERT_EQ(kem_ct.size(), 1088);
    QRSyncTabTestAccess::feedFrame(tab, kFrameKem, kem_ct);
    EXPECT_TRUE(peer.silence());
    EXPECT_TRUE(QRSyncTabTestAccess::showingError(tab));
    EXPECT_FALSE(QRSyncTabTestAccess::isOldDeviceMode(tab));
    EXPECT_FALSE(QRSyncTabTestAccess::odAuthorizationValid(tab));

    // A late-arriving approval on the wiped session must not revive it.
    QRSyncTabTestAccess::feedFrame(tab, kFrameKem, kem_ct);
    EXPECT_TRUE(peer.silence());
}

TEST(QRSyncProtocol4GateTest, OldDeviceReleasesVaultOnceAfterSignatureVerifies) {
    QRSyncTab tab(nullptr);
    SoftwareTpm* nd_signer = nullptr;
    installSigner(tab, nd_signer);
    auto session = makeSession();
    QRSyncTabTestAccess::adoptOldDeviceSession(tab, session);
    QRSyncTabTestAccess::setTransferEntries(tab, {sampleEntry("https://od.test")});
    WirePeer peer;
    QRSyncTabTestAccess::adoptSocket(tab, peer.tabSocket());

    QRSyncTabTestAccess::feedFrame(tab, kFrameNdApproval,
                                   ndApprovalWire(session, *nd_signer));
    ASSERT_TRUE(QRSyncTabTestAccess::odAuthorizationValid(tab));
    EXPECT_EQ(QRSyncTabTestAccess::peerPkNd(tab), nd_signer->getPubkey());

    auto encaps = kemEncapsulate(session.pk_nd, testAuth(session));
    const QByteArray kem_ct(reinterpret_cast<const char*>(encaps.first.data()),
                            static_cast<int>(encaps.first.size()));
    QRSyncTabTestAccess::feedFrame(tab, kFrameKem, kem_ct);
    quint8 type = 0;
    QByteArray body;
    ASSERT_TRUE(peer.readFrame(&type, &body));
    ASSERT_EQ(type, kFrameVault);
    const auto plaintext = aesGcmDecryptPayload(
        std::vector<uint8_t>(encaps.second.begin(), encaps.second.end()),
        std::vector<uint8_t>(body.constData(), body.constData() + body.size()));
    const auto entries = auth::DeserializeVault(plaintext);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries.front().website, "https://od.test");

    // The single-use session must refuse a replayed KEM frame.
    QRSyncTabTestAccess::feedFrame(tab, kFrameKem, kem_ct);
    EXPECT_TRUE(peer.silence());
}

TEST(QRSyncProtocol4GateTest, NewDeviceAutoSignsAndEncapsulatesAfterVerifiedApproval) {
    QRSyncTab tab(nullptr);
    SoftwareTpm* signer = nullptr;
    installSigner(tab, signer);
    auto session = makeSession();
    QRSyncTabTestAccess::adoptNewDeviceScan(tab, session);
    WirePeer peer;
    QRSyncTabTestAccess::adoptSocket(tab, peer.tabSocket());

    QRSyncTabTestAccess::feedFrame(tab, kFrameOdApproval, odApprovalWire(session, *signer));

    quint8 type = 0;
    QByteArray body;
    // Protocol 4: ND signs sigma_ND over (SAS || PKn' || ID') and sends it
    // together with its KEM ciphertext without waiting for another click.
    ASSERT_TRUE(peer.readFrame(&type, &body));
    EXPECT_EQ(type, kFrameNdApproval);
    const int pk_len = (static_cast<quint8>(body.at(0)) << 8) |
                       static_cast<quint8>(body.at(1));
    const std::vector<uint8_t> pk(body.constData() + 2,
                                  body.constData() + 2 + pk_len);
    const int sig_off = 2 + pk_len;
    const int sig_len = (static_cast<quint8>(body.at(sig_off)) << 8) |
                        static_cast<quint8>(body.at(sig_off + 1));
    const std::vector<uint8_t> sig(body.constData() + sig_off + 2,
                                   body.constData() + sig_off + 2 + sig_len);
    ASSERT_TRUE(signer->verify(
        newDeviceApprovalDigest(session.sas, session.pk_nd, session.id),
        sig, pk));

    ASSERT_TRUE(peer.readFrame(&type, &body));
    EXPECT_EQ(type, kFrameKem);
    EXPECT_EQ(body.size(), 1088);

    // Peer identity was captured from the verified approval.
    EXPECT_EQ(QRSyncTabTestAccess::peerPkOd(tab), signer->getPubkey());
}

TEST(QRSyncProtocol4GateTest, ImportFailureDoesNotAcknowledgeSuccess) {
    QRSyncTab tab(nullptr);  // no password manager -> import must fail
    auto session = makeSession();
    QRSyncTabTestAccess::adoptNewDeviceScan(tab, session);
    std::vector<uint8_t> noise(32, 0x5A);
    QRSyncTabTestAccess::setNoiseKey(tab, noise);
    WirePeer peer;
    QRSyncTabTestAccess::adoptSocket(tab, peer.tabSocket());

    const auto payload = auth::SerializeVault({sampleEntry("https://od.test")});
    const auto encrypted = aesGcmEncryptPayload(noise, payload);
    const QByteArray body(reinterpret_cast<const char*>(encrypted.data()),
                          static_cast<int>(encrypted.size()));

    QRSyncTabTestAccess::feedFrame(tab, kFrameVault, body);

    // No ACK may be sent when the vault could not be saved.
    EXPECT_TRUE(peer.silence());
    EXPECT_TRUE(QRSyncTabTestAccess::showingError(tab));
}

TEST(QRSyncProtocol4GateTest, SuccessfulSyncRecordsPeerDeviceKeysInVault) {
    PasswordManagerTab pm;
    // Create the local vault through the real UI path (no modal prompts).
    auto* master = pm.findChild<QLineEdit*>("masterPasswordInput");
    ASSERT_NE(master, nullptr);
    master->setText(QStringLiteral("test-master-1"));
    for (QPushButton* button : pm.findChildren<QPushButton*>()) {
        if (button->text() == QStringLiteral("Set Master Password")) {
            button->click();
            break;
        }
    }

    // --- New device side: verified approval -> import -> ack + record pkOD.
    QRSyncTab nd(&pm);
    SoftwareTpm* nd_signer = nullptr;
    installSigner(nd, nd_signer);
    auto nd_session = makeSession();
    QRSyncTabTestAccess::adoptNewDeviceScan(nd, nd_session);
    WirePeer nd_peer;
    QRSyncTabTestAccess::adoptSocket(nd, nd_peer.tabSocket());

    SoftwareTpm od_signer;
    od_signer.createKey();
    QRSyncTabTestAccess::feedFrame(nd, kFrameOdApproval,
                                   odApprovalWire(nd_session, od_signer));
    quint8 type = 0;
    QByteArray body;
    ASSERT_TRUE(nd_peer.readFrame(&type, &body));  // sigma_ND
    ASSERT_TRUE(nd_peer.readFrame(&type, &body));  // Kem
    ASSERT_EQ(type, kFrameKem);
    ASSERT_EQ(body.size(), 1088);
    // Recover the transfer key the way the old device does.
    const std::vector<uint8_t> kem_ct(body.constData(),
                                      body.constData() + body.size());
    const auto shared = auth::sync::kemDecapsulate(nd_session.sk_nd, kem_ct);
    const std::vector<uint8_t> noise(shared.begin(), shared.end());
    const auto payload = auth::SerializeVault({sampleEntry("https://od-vault.test")});
    const auto encrypted = aesGcmEncryptPayload(noise, payload);
    const QByteArray vault_body(reinterpret_cast<const char*>(encrypted.data()),
                                static_cast<int>(encrypted.size()));

    QRSyncTabTestAccess::feedFrame(nd, kFrameVault, vault_body);
    ASSERT_TRUE(nd_peer.readFrame(&type, &body));
    EXPECT_EQ(type, kFrameAck);
    QString error;
    EXPECT_TRUE(pm.isKnownPeerDeviceKey(od_signer.getPubkey(), error))
        << error.toStdString();

    // --- Old device side: verified sigma_ND + vault release + ack -> record pkND.
    QRSyncTab od(&pm);
    SoftwareTpm* od_tab_signer = nullptr;
    installSigner(od, od_tab_signer);
    auto od_session = makeSession();
    QRSyncTabTestAccess::adoptOldDeviceSession(od, od_session);
    QRSyncTabTestAccess::setTransferEntries(od, {sampleEntry("https://od-vault.test")});
    WirePeer od_peer;
    QRSyncTabTestAccess::adoptSocket(od, od_peer.tabSocket());

    QRSyncTabTestAccess::feedFrame(od, kFrameNdApproval,
                                   ndApprovalWire(od_session, *nd_signer));
    auto encaps = kemEncapsulate(od_session.pk_nd, testAuth(od_session));
    const QByteArray od_kem(reinterpret_cast<const char*>(encaps.first.data()),
                            static_cast<int>(encaps.first.size()));
    QRSyncTabTestAccess::feedFrame(od, kFrameKem, od_kem);
    ASSERT_TRUE(od_peer.readFrame(&type, &body));
    EXPECT_EQ(type, kFrameVault);
    QRSyncTabTestAccess::feedFrame(od, kFrameAck, QByteArray());
    QString od_error;
    EXPECT_TRUE(pm.isKnownPeerDeviceKey(nd_signer->getPubkey(), od_error))
        << od_error.toStdString();
}
