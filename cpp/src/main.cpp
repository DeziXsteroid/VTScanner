#include "MainWindow.h"
#include "core/AppPaths.h"

#include <QApplication>
#include <QStringList>

namespace {

void ensureGuiCommandPath() {
    QStringList pathParts = qEnvironmentVariable("PATH").split(QLatin1Char(':'), Qt::SkipEmptyParts);
    const QStringList requiredParts {
        QStringLiteral("/usr/bin"),
        QStringLiteral("/bin"),
        QStringLiteral("/usr/sbin"),
        QStringLiteral("/sbin"),
        QStringLiteral("/opt/homebrew/bin"),
        QStringLiteral("/opt/homebrew/sbin"),
        QStringLiteral("/usr/local/bin"),
        QStringLiteral("/usr/local/sbin"),
    };

    bool changed = false;
    for (const auto& part : requiredParts) {
        if (!pathParts.contains(part)) {
            pathParts.append(part);
            changed = true;
        }
    }

    if (changed || qEnvironmentVariableIsEmpty("PATH")) {
        qputenv("PATH", pathParts.join(QLatin1Char(':')).toUtf8());
    }
}

} // namespace

int main(int argc, char* argv[]) {
    ensureGuiCommandPath();
    QApplication app(argc, argv);
    app.setApplicationName("Network Tools");
    app.setOrganizationName("NetWorkTools");
    app.setApplicationVersion("1.0.6");
    nt::AppPaths::ensureRuntimeTree();

    MainWindow window;
    window.show();
    return app.exec();
}
