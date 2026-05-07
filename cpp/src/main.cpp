#include "MainWindow.h"
#include "core/AppPaths.h"

#include <QApplication>
#include <QDir>
#include <QStringList>

#include <algorithm>

namespace {

void ensureGuiCommandPath() {
#ifdef Q_OS_WIN
    QStringList pathParts = qEnvironmentVariable("PATH").split(QLatin1Char(';'), Qt::SkipEmptyParts);
    const QString windowsDir = qEnvironmentVariable("WINDIR", QStringLiteral("C:\\Windows"));
    const QStringList requiredParts {
        QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32")),
        QDir::toNativeSeparators(windowsDir),
        QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\WindowsPowerShell\\v1.0")),
        QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\OpenSSH")),
    };

    bool changed = false;
    for (const auto& part : requiredParts) {
        const auto exists = std::any_of(pathParts.cbegin(), pathParts.cend(), [&part](const QString& current) {
            return current.compare(part, Qt::CaseInsensitive) == 0;
        });
        if (!exists) {
            pathParts.append(part);
            changed = true;
        }
    }

    if (changed || qEnvironmentVariableIsEmpty("PATH")) {
        qputenv("PATH", pathParts.join(QLatin1Char(';')).toUtf8());
    }
#else
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
#endif
}

} // namespace

int main(int argc, char* argv[]) {
    ensureGuiCommandPath();
    QApplication app(argc, argv);
    app.setApplicationName("Network Tools");
    app.setOrganizationName("NetWorkTools");
    app.setApplicationVersion("1.1");
    nt::AppPaths::ensureRuntimeTree();

    MainWindow window;
    window.show();
    return app.exec();
}
