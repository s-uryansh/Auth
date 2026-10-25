#include <QApplication>
#include "MainWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("TMPS Auth");
    app.setOrganizationName("TMPS");

    MainWindow w;
#ifdef Q_OS_ANDROID
    w.showMaximized();
#else
    w.show();
#endif
    return app.exec();
}
