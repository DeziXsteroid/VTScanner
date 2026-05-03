#include "MainWindow.h"
#include "core/AppPaths.h"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Network Tools");
    app.setOrganizationName("NetWorkTools");
    app.setApplicationVersion("1.0.5");
    nt::AppPaths::ensureRuntimeTree();

    MainWindow window;
    window.show();
    return app.exec();
}
