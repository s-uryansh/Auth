#include <QApplication>
#include "MainWindow.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("TMPS Auth");
    app.setOrganizationName("TMPS");

    MainWindow w;
    w.show();
    return app.exec();
}
