#include "QRSyncTab.h"

#include <QApplication>
#include <QLabel>
#include <QCoreApplication>
#include <QEventLoop>
#include <QImage>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QThread>
#include <QHostAddress>
#include <QTcpServer>
#include <ZXing/BarcodeFormat.h>
#include <ZXing/BitMatrix.h>
#include <ZXing/ImageView.h>
#include <ZXing/MultiFormatWriter.h>
#include <ZXing/ReadBarcode.h>
#include <ZXing/ReaderOptions.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

class QRSyncTabTestAccess {
public:
    static QSize updatePreview(QRSyncTab& tab) {
        tab.od_mode_ = false;
        tab.has_camera_ = true;
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::Scanning));
        tab.camera_viewfinder_->resize(320, 240);
        tab.preview_elapsed_.invalidate();
        tab.decode_elapsed_.start();
        QThread::msleep(260);
        QImage frame_image(640, 480, QImage::Format_RGB32);
        frame_image.fill(Qt::white);
        tab.processCameraFrame(QVideoFrame(frame_image));
        return tab.camera_viewfinder_->pixmap(Qt::ReturnByValue).size();
    }

    static bool scheduleQrDecode(QRSyncTab& tab, const QImage& frame) {
        tab.od_mode_ = false;
        tab.has_camera_ = true;
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::Scanning));
        tab.camera_viewfinder_->resize(320, 240);
        tab.preview_elapsed_.invalidate();
        tab.decode_elapsed_.invalidate();
        tab.processCameraFrame(QVideoFrame(frame));
        return tab.decode_pending_;
    }

    static bool decodePending(const QRSyncTab& tab) { return tab.decode_pending_; }
    static bool showingError(const QRSyncTab& tab) {
        return tab.pages_->currentIndex() == static_cast<int>(QRSyncTab::Error);
    }
    static QPixmap renderQr(QRSyncTab& tab, const std::vector<uint8_t>& payload) {
        tab.qr_label_->resize(300, 300);
        tab.renderQRBitmap(payload);
        return tab.qr_label_->pixmap(Qt::ReturnByValue);
    }
    static void scanQr(QRSyncTab& tab, const std::vector<uint8_t>& payload) {
        tab.od_mode_ = false;
        tab.handleScannedQr(payload);
    }
    static bool reachedSasScreen(const QRSyncTab& tab) {
        return tab.pages_->currentIndex() == static_cast<int>(QRSyncTab::SAS);
    }

    static void setupOldSession(QRSyncTab& tab, std::chrono::seconds remaining) {
        tab.od_mode_ = true;
        tab.od_expiry_ = std::chrono::system_clock::now() + remaining;
        tab.session_duration_ms_ =
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        tab.session_elapsed_.start();
        tab.od_id_.fill(0xA5);
        tab.od_pk_nd_.fill(0xA5);
        tab.qr_label_->setText("Active QR");
        tab.server_->close();
        ASSERT_TRUE(tab.server_->listen(QHostAddress::LocalHost, 0));
        tab.pages_->setCurrentIndex(static_cast<int>(QRSyncTab::WaitingQR));
        tab.expiry_timer_->start();
    }

    static void fireExpiryTimer(QRSyncTab& tab) {
        ASSERT_TRUE(QMetaObject::invokeMethod(
            tab.expiry_timer_, "timeout", Qt::DirectConnection));
    }

    static bool oldDeviceMode(const QRSyncTab& tab) { return tab.od_mode_; }
    static bool serverListening(const QRSyncTab& tab) {
        return tab.server_->isListening();
    }
    static bool sessionIdCleared(const QRSyncTab& tab) {
        return std::all_of(tab.od_id_.begin(), tab.od_id_.end(),
                           [](uint8_t byte) { return byte == 0; });
    }
    static QString qrLabelText(const QRSyncTab& tab) {
        return tab.qr_label_->text();
    }
};

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QTemporaryDir test_home;
    if (!test_home.isValid()) return 1;
    qputenv("XDG_DATA_HOME", test_home.path().toUtf8());
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName("AuthTests");
    QCoreApplication::setApplicationName("QtUiFlowTests");
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(QRSyncCameraFlowTest, SelectingNewDeviceOpensScannerImmediately) {
    QRSyncTab tab(nullptr);

    QPushButton* new_device_button = nullptr;
    for (QPushButton* button : tab.findChildren<QPushButton*>()) {
        if (button->text() == QStringLiteral("New Device")) {
            new_device_button = button;
            break;
        }
    }
    ASSERT_NE(new_device_button, nullptr);

    auto* pages = tab.findChild<QStackedWidget*>();
    ASSERT_NE(pages, nullptr);

    new_device_button->click();

    auto* current_page = qobject_cast<QScrollArea*>(pages->currentWidget());
    ASSERT_NE(current_page, nullptr);
    EXPECT_EQ(current_page->widget()->objectName(), QStringLiteral("qrSyncScanningPage"));
}

TEST(QRSyncCameraFlowTest, PreviewPixmapFitsLogicalViewfinderSize) {
    QRSyncTab tab(nullptr);

    const QSize preview_size = QRSyncTabTestAccess::updatePreview(tab);

    EXPECT_LE(preview_size.width(), 320);
    EXPECT_LE(preview_size.height(), 240);
}

TEST(QRSyncCameraFlowTest, CameraFrameSchedulesQrDecodeOffTheUiCallStack) {
    QByteArray qr_payload("AUTHQR:");
    qr_payload += QByteArray(1200, 'x').toBase64();
    ZXing::MultiFormatWriter writer(ZXing::BarcodeFormat::QRCode);
    writer.setEccLevel(0);
    writer.setMargin(4);
    const ZXing::BitMatrix matrix = writer.encode(qr_payload.toStdString(), 640, 640);
    ASSERT_LE(matrix.width(), 640);
    ASSERT_LE(matrix.height(), 640);

    QImage frame(1280, 720, QImage::Format_RGB32);
    frame.fill(Qt::white);
    for (int y = 0; y < matrix.height(); ++y) {
        for (int x = 0; x < matrix.width(); ++x) {
            frame.setPixel(x + 320, y + 40,
                           matrix.get(x, y) ? qRgb(0, 0, 0) : qRgb(255, 255, 255));
        }
    }

    QRSyncTab tab(nullptr);
    EXPECT_TRUE(QRSyncTabTestAccess::scheduleQrDecode(tab, frame));
    QElapsedTimer wait_timer;
    wait_timer.start();
    while (QRSyncTabTestAccess::decodePending(tab) && wait_timer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QThread::msleep(1);
    }
    EXPECT_FALSE(QRSyncTabTestAccess::decodePending(tab));
    EXPECT_TRUE(QRSyncTabTestAccess::showingError(tab));
}

TEST(QRSyncCameraFlowTest, GeneratedProtocol4QrUsesNativePixelsAndRoundTrips) {
    QTcpServer peer;
    ASSERT_TRUE(peer.listen(QHostAddress::LocalHost, 0));

    auth::sync::QRPayload payload;
    payload.id.fill(0x11);
    payload.pk_nd.fill(0x42);
    payload.conn_info = QString("127.0.0.1:%1").arg(peer.serverPort()).toStdString();
    payload.expiry = std::chrono::system_clock::now() +
                     std::chrono::seconds(auth::sync::kSessionExpirySeconds);
    const auto serialized = auth::sync::serializeQR(payload);

    QRSyncTab tab(nullptr);
    const QPixmap qr = QRSyncTabTestAccess::renderQr(tab, serialized);
    ASSERT_EQ(qr.devicePixelRatio(), 2.0);
    EXPECT_EQ(qr.size(), QSize(600, 600));

    const QImage gray = qr.toImage().convertToFormat(QImage::Format_Grayscale8);
    const ZXing::ImageView view(gray.constBits(), gray.width(), gray.height(),
                                ZXing::ImageFormat::Lum, gray.bytesPerLine());
    const auto barcode = ZXing::ReadBarcode(
        view, ZXing::ReaderOptions().setFormats(ZXing::BarcodeFormat::QRCode)
                                       .setTryHarder(true));
    ASSERT_TRUE(barcode.isValid());

    const auto& bytes = barcode.bytes();
    const QByteArray text(reinterpret_cast<const char*>(bytes.data()),
                          static_cast<qsizetype>(bytes.size()));
    ASSERT_TRUE(text.startsWith(QByteArrayLiteral("AUTHQR:")));
    const QByteArray decoded = QByteArray::fromBase64(
        text.mid(7), QByteArray::AbortOnBase64DecodingErrors);
    EXPECT_EQ(decoded.size(), static_cast<qsizetype>(serialized.size()));
    ASSERT_EQ(decoded.size(), static_cast<qsizetype>(serialized.size()));
    EXPECT_EQ(std::memcmp(decoded.constData(), serialized.data(), serialized.size()), 0);

    EXPECT_TRUE(QRSyncTabTestAccess::scheduleQrDecode(tab, qr.toImage()));
    QElapsedTimer wait_timer;
    wait_timer.start();
    while (QRSyncTabTestAccess::decodePending(tab) && wait_timer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QThread::msleep(1);
    }
    EXPECT_FALSE(QRSyncTabTestAccess::decodePending(tab));
    EXPECT_TRUE(QRSyncTabTestAccess::reachedSasScreen(tab));
}

TEST(QRSyncCameraFlowTest, ScannedQrCanCreateClientSocketAfterSessionReset) {
    QTcpServer peer;
    ASSERT_TRUE(peer.listen(QHostAddress::LocalHost, 0));

    auth::sync::QRPayload qr;
    qr.id.fill(0x11);
    qr.pk_nd.fill(0x22);
    qr.conn_info = QString("127.0.0.1:%1").arg(peer.serverPort()).toStdString();
    qr.expiry = std::chrono::system_clock::now() +
                std::chrono::seconds(auth::sync::kSessionExpirySeconds);

    QRSyncTab tab(nullptr);
    QRSyncTabTestAccess::scanQr(tab, auth::sync::serializeQR(qr));
    EXPECT_TRUE(QRSyncTabTestAccess::reachedSasScreen(tab));
}

TEST(QRSyncSessionTimerTest, DisplaysFiveMinuteCountdownAndExpiresTheSession) {
    QRSyncTab tab(nullptr);
    QLabel* countdown = tab.findChild<QLabel*>("qrExpiryCountdown");
    ASSERT_NE(countdown, nullptr);

    QRSyncTabTestAccess::setupOldSession(tab, std::chrono::minutes(5));
    QRSyncTabTestAccess::fireExpiryTimer(tab);
    EXPECT_EQ(countdown->text(), QStringLiteral("Expires in 5:00"));

    QRSyncTabTestAccess::setupOldSession(tab, std::chrono::seconds(-1));
    QRSyncTabTestAccess::fireExpiryTimer(tab);

    EXPECT_FALSE(QRSyncTabTestAccess::oldDeviceMode(tab));
    EXPECT_FALSE(QRSyncTabTestAccess::serverListening(tab));
    EXPECT_TRUE(QRSyncTabTestAccess::sessionIdCleared(tab));
    EXPECT_EQ(QRSyncTabTestAccess::qrLabelText(tab), QString());
}
