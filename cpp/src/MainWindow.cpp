#include "MainWindow.h"

#include "core/AppPaths.h"
#include "core/SettingsService.h"
#include "core/SnapshotService.h"
#include "core/TerminalSanitizer.h"
#include "core/VendorDbService.h"
#include "network/HttpRequestService.h"
#include "network/NetworkScanService.h"
#include "network/SerialSession.h"
#include "network/SshProcessSession.h"
#include "network/TcpClientSession.h"
#include "network/TelnetSession.h"
#include "network/UdpSocketSession.h"
#include "widgets/CodeEditor.h"

#include <algorithm>
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractSocket>
#include <QBrush>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHostAddress>
#include <QHostInfo>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QMenu>
#include <QMenuBar>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRadialGradient>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyleFactory>
#include <QTableWidgetSelectionRange>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QSerialPortInfo>
#include <QTabWidget>
#include <QTextStream>
#include <QThread>
#include <QTimer>
#include <QTextCursor>
#include <QTextEdit>
#include <QToolTip>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QUrl>
#include <QVariantAnimation>
#include <QVariant>
#include <QVBoxLayout>
#include <QtConcurrent>

#include <cmath>

namespace {

constexpr auto kWindowTitle = "Сканер IP - Network Tools";

enum ScanColumn {
    ScanColumnIp = 0,
    ScanColumnPing,
    ScanColumnMac,
    ScanColumnVendor,
    ScanColumnHostName,
    ScanColumnWeb,
    ScanColumnGateway,
    ScanColumnPort,
    ScanColumnType,
    ScanColumnCount,
};

QString scanColumnKey(int column) {
    switch (column) {
    case ScanColumnIp: return QStringLiteral("ip");
    case ScanColumnPing: return QStringLiteral("ping");
    case ScanColumnMac: return QStringLiteral("mac");
    case ScanColumnVendor: return QStringLiteral("vendor");
    case ScanColumnHostName: return QStringLiteral("hostname");
    case ScanColumnWeb: return QStringLiteral("web");
    case ScanColumnGateway: return QStringLiteral("gateway");
    case ScanColumnPort: return QStringLiteral("port");
    case ScanColumnType: return QStringLiteral("type");
    default: return QStringLiteral("col");
    }
}

bool scanColumnVisibleByDefault(int column) {
    return column != ScanColumnHostName && column != ScanColumnWeb;
}

int defaultScanColumnWidth(int column) {
    switch (column) {
    case ScanColumnIp: return 162;
    case ScanColumnPing: return 70;
    case ScanColumnMac: return 126;
    case ScanColumnVendor: return 176;
    case ScanColumnHostName: return 160;
    case ScanColumnWeb: return 166;
    case ScanColumnGateway: return 128;
    case ScanColumnPort: return 108;
    case ScanColumnType: return 78;
    default: return 96;
    }
}

QString normalizedScanProfileForUi(QString profile) {
    profile = profile.trimmed().toLower();
    if (profile == QStringLiteral("fast") || profile == QStringLiteral("reliable")) {
        return profile;
    }
    return QStringLiteral("balanced");
}

int autoScanWorkerCountForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfileForUi(profile);
    const int cores = qMax(2, QThread::idealThreadCount());
    if (normalized == QStringLiteral("fast")) {
        return qBound(24, cores * 6, 64);
    }
    if (normalized == QStringLiteral("reliable")) {
        return qBound(6, cores * 3, 24);
    }
    return qBound(16, cores * 5, 48);
}

QString ipScanLogPath() {
    nt::AppPaths::ensureRuntimeTree();
    return QDir(nt::AppPaths::logsDir()).filePath(QStringLiteral("ip-scan.log"));
}

void ensureIpScanLogExists(const QString& path) {
    if (QFileInfo::exists(path)) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }
    QTextStream out(&file);
    out << "Network Tools IP scan log\n";
    out << "created_at=" << QDateTime::currentDateTime().toString(Qt::ISODateWithMs) << '\n';
    out << "no scan has been started in this session yet\n";
}

void openIpScanLogFile() {
    const QString path = ipScanLogPath();
    ensureIpScanLogExists(path);
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

QString uiText(const QString& language, const char* ru, const char* en) {
    return QString::fromUtf8(language == QStringLiteral("en") ? en : ru);
}

QString uiText(const nt::SettingsService* settings, const char* ru, const char* en) {
    return uiText(settings != nullptr ? settings->language() : QStringLiteral("ru"), ru, en);
}

bool isEnglishUi(const nt::SettingsService* settings) {
    return settings != nullptr && settings->language() == QStringLiteral("en");
}

QString scanProfileTitle(const nt::SettingsService* settings, const QString& profile) {
    const QString normalized = normalizedScanProfileForUi(profile);
    if (normalized == QStringLiteral("fast")) {
        return uiText(settings, "Быстрый", "Fast");
    }
    if (normalized == QStringLiteral("reliable")) {
        return uiText(settings, "Слабая сеть", "Weak network");
    }
    return uiText(settings, "Баланс", "Balanced");
}

QString scanProfileDescription(const nt::SettingsService* settings, const QString& profile) {
    const QString normalized = normalizedScanProfileForUi(profile);
    if (normalized == QStringLiteral("fast")) {
        return uiText(settings, "Быстрый режим: хорошая сеть, короткие таймауты, быстрый сбор.", "Fast mode: good network, short timeouts, quick collection.");
    }
    if (normalized == QStringLiteral("reliable")) {
        return uiText(settings, "Слабая сеть: больше ожидания и повторов для полной информации.", "Weak network: longer waits and retries for complete information.");
    }
    return uiText(settings, "Баланс: средняя скорость и усиленный сбор информации.", "Balanced: medium speed with stronger information collection.");
}

QString localizedWindowTitle(const nt::SettingsService* settings) {
    return uiText(settings, "Сканер IP - Network Tools", "IP Scanner - Network Tools");
}

QString localizedConnectText(const nt::SettingsService* settings, bool connected) {
    return uiText(settings, connected ? "Отключить" : "Подключить", connected ? "Disconnect" : "Connect");
}

QString localizedUdpToggleText(const nt::SettingsService* settings, bool open) {
    return uiText(settings, open ? "Закрыть" : "Открыть", open ? "Close" : "Open");
}

QString normalizedParityKey(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("even") || normalized == QStringLiteral("чет") || normalized == QStringLiteral("чёт")) {
        return QStringLiteral("even");
    }
    if (normalized == QStringLiteral("odd") || normalized == QStringLiteral("нечет") || normalized == QStringLiteral("нечёт")) {
        return QStringLiteral("odd");
    }
    return QStringLiteral("none");
}

QString normalizedFlowControlKey(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("hardware") || normalized == QStringLiteral("rts/cts")) {
        return QStringLiteral("hardware");
    }
    if (normalized == QStringLiteral("software") || normalized == QStringLiteral("xon/xoff")) {
        return QStringLiteral("software");
    }
    return QStringLiteral("none");
}

QString normalizedEolKey(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("cr")) {
        return QStringLiteral("cr");
    }
    if (normalized == QStringLiteral("lf")) {
        return QStringLiteral("lf");
    }
    if (normalized == QStringLiteral("crlf")) {
        return QStringLiteral("crlf");
    }
    return QStringLiteral("none");
}

void setComboByData(QComboBox* combo, const QString& key) {
    if (combo == nullptr) {
        return;
    }
    int index = combo->findData(key);
    if (index < 0) {
        index = combo->findText(key);
    }
    combo->setCurrentIndex(index >= 0 ? index : 0);
}

QString comboValue(const QComboBox* combo) {
    if (combo == nullptr) {
        return {};
    }
    const QVariant data = combo->currentData();
    return data.isValid() ? data.toString() : combo->currentText();
}

QString localizedRequestStatusDivider() {
    return QStringLiteral("-------------------------- Status -------------------------");
}

QString localizedRequestBodyDivider() {
    return QStringLiteral("--------------------------- Body --------------------------");
}

QString localizedRequestEndDivider() {
    return QStringLiteral("--------------------------- End ---------------------------");
}

QString comparisonBadgeText() {
    return QStringLiteral("new!");
}

QString localizedFoundDevicesText(const nt::SettingsService* settings, int count) {
    return isEnglishUi(settings)
        ? QStringLiteral("Devices: %1").arg(count)
        : QStringLiteral("Устройств: %1").arg(count);
}

QString localizedScanIdleText(const nt::SettingsService* settings) {
    return isEnglishUi(settings)
        ? QStringLiteral("Scan idle")
        : QStringLiteral("Ожидание сканирования");
}

QString localizedScanScanningText(const nt::SettingsService* settings) {
    Q_UNUSED(settings)
    return QStringLiteral("Scanning...");
}

QString localizedScanPolishingText(const nt::SettingsService* settings) {
    Q_UNUSED(settings)
    return QStringLiteral("Polishing...");
}

QString localizedScanRefreshingText(const nt::SettingsService* settings) {
    Q_UNUSED(settings)
    return QStringLiteral("Refreshing...");
}

QString localizedScanFinishedText(const nt::SettingsService* settings, int durationMs) {
    return isEnglishUi(settings)
        ? QStringLiteral("Scan finished in %1 s").arg(durationMs / 1000.0, 0, 'f', 2)
        : QStringLiteral("Сканирование завершено за %1 c").arg(durationMs / 1000.0, 0, 'f', 2);
}

QString localizedScanRefreshFinishedText(const nt::SettingsService* settings, int updated, int added, int removed, int durationMs) {
    return isEnglishUi(settings)
        ? QStringLiteral("Refresh: updated %1 | added %2 | removed %3 | %4 s").arg(updated).arg(added).arg(removed).arg(durationMs / 1000.0, 0, 'f', 2)
        : QStringLiteral("Обновление: изменено %1 | добавлено %2 | удалено %3 | %4 c").arg(updated).arg(added).arg(removed).arg(durationMs / 1000.0, 0, 'f', 2);
}

QString localizedScanSummaryText(const nt::SettingsService* settings, int activeCount, int onlineCount, int macCount) {
    return isEnglishUi(settings)
        ? QStringLiteral("Active: %1 | Online: %2 | MAC: %3").arg(activeCount).arg(onlineCount).arg(macCount)
        : QStringLiteral("Активных: %1 | Онлайн: %2 | MAC: %3").arg(activeCount).arg(onlineCount).arg(macCount);
}

QString localizedComparisonModeText(const nt::SettingsService* settings) {
    return isEnglishUi(settings)
        ? QStringLiteral("Comparison mode enabled! Scan again now.")
        : QStringLiteral("Режим сравнения включен! Теперь отсканируйте еще раз.");
}

QString localizedMissingText(const nt::SettingsService* settings) {
    return isEnglishUi(settings) ? QStringLiteral("none") : QStringLiteral("отсутствует");
}

QString localizedHostStatusText(const nt::SettingsService* settings, nt::HostStatus status) {
    switch (status) {
    case nt::HostStatus::Online:
        return isEnglishUi(settings) ? QStringLiteral("Online") : QStringLiteral("Онлайн");
    case nt::HostStatus::Offline:
        return isEnglishUi(settings) ? QStringLiteral("Offline") : QStringLiteral("Офлайн");
    case nt::HostStatus::Unknown:
    default:
        return localizedMissingText(settings);
    }
}

QString localizedHostStatusIndicator(const nt::SettingsService* settings, nt::HostStatus status) {
    switch (status) {
    case nt::HostStatus::Online:
        return isEnglishUi(settings) ? QStringLiteral("\u25cf Online") : QStringLiteral("\u25cf Онлайн");
    case nt::HostStatus::Offline:
        return isEnglishUi(settings) ? QStringLiteral("\u25cf Offline") : QStringLiteral("\u25cf Офлайн");
    case nt::HostStatus::Unknown:
    default:
        return localizedMissingText(settings);
    }
}

QString scanPortCellText(const nt::SettingsService* settings, const QString& portText) {
    const QString value = portText.trimmed();
    if (value.isEmpty() || value == QStringLiteral("-") || value == QStringLiteral("[n/a]")) {
        return isEnglishUi(settings) ? QStringLiteral("not open") : QStringLiteral("отсутствует");
    }
    return value;
}

QString normalizedTypeText(const nt::SettingsService* settings, const QString& typeHint) {
    const QString value = typeHint.trimmed();
    if (value.isEmpty() || value == QStringLiteral("-") || value == QStringLiteral("[n/a]")) {
        return localizedMissingText(settings);
    }
    return value;
}

QString normalizedHostNameText(const nt::SettingsService* settings, const QString& hostName) {
    const QString value = hostName.trimmed();
    if (value.isEmpty() || value == QStringLiteral("-") || value == QStringLiteral("[n/a]")) {
        return localizedMissingText(settings);
    }
    return value;
}

QString normalizedWebDetectText(const nt::SettingsService* settings, const QString& webDetect) {
    const QString value = webDetect.trimmed();
    if (value.isEmpty() || value == QStringLiteral("-") || value == QStringLiteral("[n/a]")) {
        return localizedMissingText(settings);
    }
    return value;
}

QString firstServiceUrl(const QString& value) {
    for (const auto& part : value.split(QStringLiteral(" | "), Qt::SkipEmptyParts)) {
        const QString candidate = part.trimmed();
        if (candidate.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive)
            || candidate.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)
            || candidate.startsWith(QStringLiteral("rtsp://"), Qt::CaseInsensitive)) {
            return candidate;
        }
    }
    return {};
}

QString scanTypeCellText(const nt::SettingsService* settings, const QString& typeHint, bool isNewHost) {
    const QString baseText = normalizedTypeText(settings, typeHint);
    Q_UNUSED(isNewHost);
    return baseText;
}

QString scanIpCellText(const QString& ip, bool isNewHost) {
    return isNewHost ? QStringLiteral("%1  %2").arg(ip, comparisonBadgeText()) : ip;
}

QString scanIpFromItem(const QTableWidgetItem* item) {
    if (item == nullptr) {
        return {};
    }
    const QString rawIp = item->data(Qt::UserRole).toString().trimmed();
    return rawIp.isEmpty() ? item->text().section(QLatin1Char(' '), 0, 0).trimmed() : rawIp;
}

QList<quint16> commonTcpAutoPorts() {
    return {
        22, 23, 80, 81, 135, 139, 443, 445, 548, 554, 631,
        1883, 3306, 3389, 5900, 8000, 8008, 8080, 8443, 9100, 62078
    };
}

QList<quint16> commonUdpAutoPorts() {
    return {
        53, 67, 68, 69, 123, 137, 138, 161, 500, 1900,
        3702, 4500, 5353, 5355, 5683, 52381
    };
}

quint16 detectOpenTcpPort(const QString& host, quint16 fallbackPort, int timeoutMs = 170) {
    const QList<quint16> ports = commonTcpAutoPorts();
    QList<quint16> ordered;
    if (fallbackPort > 0) {
        ordered.append(fallbackPort);
    }
    for (const auto port : ports) {
        if (!ordered.contains(port)) {
            ordered.append(port);
        }
    }

    for (const auto port : ordered) {
        QTcpSocket socket;
        socket.connectToHost(host, port);
        if (socket.waitForConnected(timeoutMs)) {
            socket.disconnectFromHost();
            return port;
        }
        socket.abort();
        qApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers);
    }
    return 0;
}

quint16 detectResponsiveUdpPort(const QString& host, quint16 fallbackPort, const QByteArray& probePayload, int timeoutMs = 180) {
    const auto addresses = QHostInfo::fromName(host).addresses();
    if (addresses.isEmpty()) {
        return 0;
    }

    const QList<quint16> ports = commonUdpAutoPorts();
    QList<quint16> ordered;
    if (fallbackPort > 0) {
        ordered.append(fallbackPort);
    }
    for (const auto port : ports) {
        if (!ordered.contains(port)) {
            ordered.append(port);
        }
    }

    const QHostAddress target = addresses.first();
    const QByteArray payload = probePayload.isEmpty() ? QByteArray(1, '\0') : probePayload.left(256);
    for (const auto port : ordered) {
        QUdpSocket socket;
        if (!socket.bind(QHostAddress::AnyIPv4, 0, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
            continue;
        }
        socket.writeDatagram(payload, target, port);
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < timeoutMs) {
            if (!socket.waitForReadyRead(qMax(25, timeoutMs - static_cast<int>(timer.elapsed())))) {
                continue;
            }
            while (socket.hasPendingDatagrams()) {
                QHostAddress sender;
                quint16 senderPort = 0;
                QByteArray data;
                data.resize(static_cast<int>(socket.pendingDatagramSize()));
                socket.readDatagram(data.data(), data.size(), &sender, &senderPort);
                if (senderPort == port) {
                    return port;
                }
            }
        }
        qApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers);
    }
    return 0;
}

QString scanPopupTitle(const nt::SettingsService* settings, int column) {
    switch (column) {
    case ScanColumnPort:
        return uiText(settings, "Открытые порты", "Open ports");
    case ScanColumnWeb:
        return QStringLiteral("Web");
    case ScanColumnHostName:
        return QStringLiteral("Hostname");
    default:
        return {};
    }
}

QString scanPopupValue(const QString& value, int column) {
    QString normalized = value.trimmed();
    if (normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized.compare(QStringLiteral("none"), Qt::CaseInsensitive) == 0
        || normalized.compare(QStringLiteral("отсутствует"), Qt::CaseInsensitive) == 0
        || normalized.compare(QStringLiteral("not open"), Qt::CaseInsensitive) == 0) {
        return {};
    }

    QStringList parts;
    if (column == ScanColumnPort) {
        parts = normalized.split(QLatin1Char(','), Qt::SkipEmptyParts);
    } else if (column == ScanColumnWeb) {
        parts = normalized.split(QStringLiteral(" | "), Qt::SkipEmptyParts);
    }
    if (parts.isEmpty()) {
        return normalized;
    }

    QStringList cleaned;
    cleaned.reserve(parts.size());
    for (QString part : parts) {
        part = part.trimmed();
        if (!part.isEmpty() && !cleaned.contains(part)) {
            cleaned.append(part);
        }
    }
    return cleaned.join(QLatin1Char('\n'));
}

QString scanColumnTitle(const nt::SettingsService* settings, int column) {
    switch (column) {
    case ScanColumnIp: return QStringLiteral("IP");
    case ScanColumnPing: return uiText(settings, "Пинг", "Ping");
    case ScanColumnMac: return QStringLiteral("MAC");
    case ScanColumnVendor: return uiText(settings, "Вендор", "Vendor");
    case ScanColumnHostName: return QStringLiteral("Hostname");
    case ScanColumnWeb: return QStringLiteral("Web");
    case ScanColumnGateway: return uiText(settings, "Шлюз IP", "Gateway IP");
    case ScanColumnPort: return uiText(settings, "Откр. порт", "Open port");
    case ScanColumnType: return uiText(settings, "Тип", "Type");
    default: return QStringLiteral("?");
    }
}

QString scanRecordSearchBlob(const nt::ScanRecord& record) {
    return QStringList{
        record.ip,
        record.pingDisplay,
        record.mac,
        record.vendor,
        record.hostName,
        record.webDetect,
        record.gateway,
        record.port,
        record.typeHint,
    }.join(QLatin1Char(' ')).toLower();
}

bool scanRecordMatchesFilter(const nt::ScanRecord& record, const QString& needle) {
    if (needle.trimmed().isEmpty()) {
        return true;
    }
    return scanRecordSearchBlob(record).contains(needle.trimmed().toLower());
}

QIcon scanGearIcon(const QColor& color) {
    QPixmap pixmap(18, 18);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.translate(9.0, 9.0);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);

    for (int tooth = 0; tooth < 8; ++tooth) {
        painter.save();
        painter.rotate(tooth * 45.0);
        painter.drawRoundedRect(QRectF(-1.15, -8.0, 2.3, 3.4), 0.7, 0.7);
        painter.restore();
    }

    painter.drawEllipse(QPointF(0.0, 0.0), 5.3, 5.3);
    painter.setCompositionMode(QPainter::CompositionMode_Clear);
    painter.drawEllipse(QPointF(0.0, 0.0), 2.15, 2.15);
    return QIcon(pixmap);
}

QIcon scanGaugeIcon(const QColor& color, const QString& profile) {
    QPixmap pixmap(20, 20);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    const QRectF arcRect(3.0, 4.0, 14.0, 14.0);
    painter.setPen(QPen(QColor("#ff6b6b"), 1.9, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(Qt::NoBrush);
    painter.drawArc(arcRect, 132 * 16, 42 * 16);
    painter.setPen(QPen(QColor("#f2c94c"), 1.9, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawArc(arcRect, 82 * 16, 42 * 16);
    painter.setPen(QPen(QColor("#6fd27f"), 1.9, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawArc(arcRect, 32 * 16, 42 * 16);

    const QString normalized = normalizedScanProfileForUi(profile);
    const qreal angleDeg = normalized == QStringLiteral("fast")
        ? 37.0
        : (normalized == QStringLiteral("reliable") ? 143.0 : 90.0);
    const QPointF center(10.0, 14.0);
    const qreal radians = angleDeg * 3.14159265358979323846 / 180.0;
    const QPointF needle(center.x() + std::cos(radians) * 6.2,
                         center.y() - std::sin(radians) * 6.2);
    painter.setPen(QPen(color, 1.55, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawLine(center, needle);
    painter.setBrush(color);
    painter.drawEllipse(center, 1.45, 1.45);
    return QIcon(pixmap);
}

QIcon scanBulbIcon(const QColor& color, bool enabled) {
    QPixmap pixmap(20, 20);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    const QColor bulbColor = enabled ? QColor("#f2c94c") : color;
    painter.setPen(QPen(bulbColor, 1.55, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(enabled ? QColor(242, 201, 76, 80) : Qt::NoBrush);
    painter.drawEllipse(QRectF(5.3, 2.8, 9.4, 10.4));
    painter.drawLine(QPointF(7.2, 13.8), QPointF(12.8, 13.8));
    painter.drawLine(QPointF(7.8, 16.1), QPointF(12.2, 16.1));
    painter.drawLine(QPointF(8.7, 18.0), QPointF(11.3, 18.0));
    if (enabled) {
        painter.setPen(QPen(QColor("#f7df7a"), 1.1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter.drawLine(QPointF(3.0, 6.0), QPointF(1.6, 5.0));
        painter.drawLine(QPointF(17.0, 6.0), QPointF(18.4, 5.0));
        painter.drawLine(QPointF(10.0, 1.2), QPointF(10.0, 0.2));
    }
    return QIcon(pixmap);
}

int pingMillisecondsFromText(const QString& value) {
    const auto match = QRegularExpression(QStringLiteral("(\\d+)\\s*ms"), QRegularExpression::CaseInsensitiveOption).match(value);
    if (!match.hasMatch()) {
        return -1;
    }
    bool ok = false;
    const int ms = match.captured(1).toInt(&ok);
    return ok ? ms : -1;
}

bool pingHealthBrushes(const QString& value, QColor* background, QColor* foreground) {
    const int ms = pingMillisecondsFromText(value);
    if (ms < 0) {
        return false;
    }
    if (ms <= 30) {
        *background = QColor("#16351f");
        *foreground = QColor("#8ff0a4");
    } else if (ms <= 100) {
        *background = QColor("#3a3217");
        *foreground = QColor("#f2d16b");
    } else if (ms <= 200) {
        *background = QColor("#3e2818");
        *foreground = QColor("#ffb16e");
    } else {
        *background = QColor("#421d22");
        *foreground = QColor("#ff808b");
    }
    return true;
}

struct SnmpParsedLine {
    QString oid;
    QString rawType;
    QString value;
    bool valid {false};
};

SnmpParsedLine parseSnmpLine(const QString& line) {
    const QString trimmed = line.trimmed();
    if (trimmed.isEmpty()
        || trimmed.startsWith(QStringLiteral("Timeout"), Qt::CaseInsensitive)
        || trimmed.startsWith(QStringLiteral("No Such"), Qt::CaseInsensitive)
        || trimmed.startsWith(QStringLiteral("No more variables"), Qt::CaseInsensitive)) {
        return {};
    }

    const QRegularExpression typedPattern(QStringLiteral(R"(^(.+?)\s*=\s*([A-Za-z0-9\-]+)\s*:\s*(.*)$)"));
    const auto typedMatch = typedPattern.match(trimmed);
    if (typedMatch.hasMatch()) {
        return {
            typedMatch.captured(1).trimmed(),
            typedMatch.captured(2).trimmed(),
            typedMatch.captured(3).trimmed(),
            true,
        };
    }

    const QRegularExpression plainPattern(QStringLiteral(R"(^(.+?)\s*=\s*(.*)$)"));
    const auto plainMatch = plainPattern.match(trimmed);
    if (plainMatch.hasMatch()) {
        return {
            plainMatch.captured(1).trimmed(),
            QStringLiteral("string"),
            plainMatch.captured(2).trimmed(),
            true,
        };
    }
    return {};
}

QString snmpValueDisplayText(const QString& rawType, const QString& value) {
    QString text = value.trimmed();
    const QString normalizedType = rawType.trimmed().toLower();
    if ((normalizedType == QStringLiteral("string") || normalizedType == QStringLiteral("octetstr"))
        && text.size() >= 2
        && text.startsWith(QLatin1Char('"'))
        && text.endsWith(QLatin1Char('"'))) {
        text = text.mid(1, text.size() - 2);
    }
    return text;
}

QString snmpTypeDisplayText(const QString& rawType) {
    const QString normalized = rawType.trimmed().toLower();
    return normalized.isEmpty() ? QStringLiteral("-") : normalized;
}

QString snmpSetTypeToken(const QString& rawType) {
    const QString normalized = rawType.trimmed().toLower();
    if (normalized == QStringLiteral("integer") || normalized == QStringLiteral("integer32")) {
        return QStringLiteral("i");
    }
    if (normalized == QStringLiteral("string") || normalized == QStringLiteral("octetstr")) {
        return QStringLiteral("s");
    }
    if (normalized == QStringLiteral("oid")) {
        return QStringLiteral("o");
    }
    if (normalized == QStringLiteral("ipaddress")) {
        return QStringLiteral("a");
    }
    if (normalized == QStringLiteral("gauge32")
        || normalized == QStringLiteral("counter32")
        || normalized == QStringLiteral("unsigned32")) {
        return QStringLiteral("u");
    }
    if (normalized == QStringLiteral("timeticks")) {
        return QStringLiteral("t");
    }
    if (normalized == QStringLiteral("hex-string")) {
        return QStringLiteral("x");
    }
    return {};
}

QString executableToolPath(const QString& name) {
    const QString bundled = nt::AppPaths::bundledToolPath(name);
    if (QFileInfo::exists(bundled)) {
        return bundled;
    }

    const QString fromPath = QStandardPaths::findExecutable(name);
    if (!fromPath.isEmpty()) {
        return fromPath;
    }

    QStringList candidates;
#ifdef Q_OS_MACOS
    candidates << QStringLiteral("/usr/bin/%1").arg(name)
               << QStringLiteral("/opt/homebrew/bin/%1").arg(name)
               << QStringLiteral("/usr/local/bin/%1").arg(name);
#elif defined(Q_OS_LINUX)
    candidates << QStringLiteral("/usr/bin/%1").arg(name)
               << QStringLiteral("/usr/sbin/%1").arg(name)
               << QStringLiteral("/bin/%1").arg(name)
               << QStringLiteral("/sbin/%1").arg(name);
#elif defined(Q_OS_WIN)
    const QString windowsDir = qEnvironmentVariable("WINDIR", QStringLiteral("C:\\Windows"));
    candidates << QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\") + name + QStringLiteral(".exe"))
               << QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\OpenSSH\\") + name + QStringLiteral(".exe"))
               << QDir::toNativeSeparators(QStringLiteral("C:\\Net-SNMP\\bin\\") + name + QStringLiteral(".exe"))
               << QDir::toNativeSeparators(QStringLiteral("C:\\Program Files\\Net-SNMP\\bin\\") + name + QStringLiteral(".exe"))
               << QDir::toNativeSeparators(QStringLiteral("C:\\Program Files (x86)\\Net-SNMP\\bin\\") + name + QStringLiteral(".exe"));
#endif

    for (const auto& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

QStringList snmpMibDirectoriesForTool(const QString& toolPath) {
    QStringList dirs;
    const auto addIfExists = [&dirs](const QString& path) {
        const QFileInfo info(QDir::cleanPath(path));
        if (!info.exists() || !info.isDir()) {
            return;
        }
        const QString absolute = QDir::toNativeSeparators(info.absoluteFilePath());
        if (!dirs.contains(absolute, Qt::CaseInsensitive)) {
            dirs << absolute;
        }
    };

    const QDir appDir(QCoreApplication::applicationDirPath());
    const QDir binDir(QFileInfo(toolPath).absolutePath());
    addIfExists(appDir.filePath(QStringLiteral("share/snmp/mibs")));
    addIfExists(appDir.filePath(QStringLiteral("../Resources/share/snmp/mibs")));
    addIfExists(binDir.filePath(QStringLiteral("../share/snmp/mibs")));
#ifdef Q_OS_WIN
    addIfExists(QStringLiteral("C:/Net-SNMP/share/snmp/mibs"));
    addIfExists(QStringLiteral("C:/Program Files/Net-SNMP/share/snmp/mibs"));
    addIfExists(QStringLiteral("C:/Program Files (x86)/Net-SNMP/share/snmp/mibs"));
#endif
    return dirs;
}

void configureSnmpProcessEnvironment(QProcess* process, const QString& toolPath) {
    if (process == nullptr) {
        return;
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QStringList mibDirs = snmpMibDirectoriesForTool(toolPath);
    if (!mibDirs.isEmpty()) {
#ifdef Q_OS_WIN
        env.insert(QStringLiteral("MIBDIRS"), mibDirs.join(QLatin1Char(';')));
#else
        env.insert(QStringLiteral("MIBDIRS"), mibDirs.join(QLatin1Char(':')));
#endif
        if (!env.contains(QStringLiteral("MIBS")) || env.value(QStringLiteral("MIBS")).trimmed().isEmpty()) {
            env.insert(QStringLiteral("MIBS"), QStringLiteral("+ALL"));
        }
    }
    process->setProcessEnvironment(env);
}

QString missingToolText(const nt::SettingsService* settings, const QString& name) {
    const QString installHint =
#ifdef Q_OS_MACOS
        QStringLiteral("brew install net-snmp");
#elif defined(Q_OS_LINUX)
        QStringLiteral("sudo apt install snmp");
#elif defined(Q_OS_WIN)
        QStringLiteral("Install Net-SNMP or add the tool folder to PATH.");
#else
        QString();
#endif
    const QString base = uiText(settings, "Не найдена внешняя утилита: %1", "External tool was not found: %1").arg(name);
    if (installHint.isEmpty()) {
        return base;
    }
    return uiText(settings, "%1\nУстановите пакет: %2", "%1\nInstall package: %2").arg(base, installHint);
}

bool snmpUsesCommunity(const QString& version) {
    const QString normalized = version.trimmed().toLower();
    return normalized.isEmpty() || normalized == QStringLiteral("1") || normalized == QStringLiteral("2c");
}

QString snmpSymbolicObjectName(QString oid) {
    oid = oid.trimmed();
    const int mibSeparator = oid.indexOf(QStringLiteral("::"));
    if (mibSeparator < 0) {
        return oid;
    }
    const int lastDot = oid.lastIndexOf(QLatin1Char('.'));
    if (lastDot <= mibSeparator) {
        return oid;
    }
    const QString suffix = oid.mid(lastDot + 1);
    const bool numericSuffix = !suffix.isEmpty() && std::all_of(suffix.begin(), suffix.end(), [](const QChar ch) {
        return ch.isDigit();
    });
    return numericSuffix ? oid.left(lastDot) : oid;
}

QString prettifySnmpObjectLabel(QString oid) {
    QString symbol = snmpSymbolicObjectName(oid);
    if (symbol.contains(QStringLiteral("::"))) {
        symbol = symbol.section(QStringLiteral("::"), 1);
    }
    symbol.replace(QLatin1Char('-'), QLatin1Char(' '));
    symbol.replace(QRegularExpression(QStringLiteral("([a-z0-9])([A-Z])")), QStringLiteral("\\1 \\2"));
    symbol.replace(QRegularExpression(QStringLiteral("([A-Z]+)([A-Z][a-z])")), QStringLiteral("\\1 \\2"));
    symbol = symbol.simplified();
    if (symbol.isEmpty()) {
        return QStringLiteral("Параметр устройства");
    }
    if (!symbol.isEmpty()) {
        symbol[0] = symbol.at(0).toUpper();
    }
    return symbol;
}

QString describeOidLabel(const nt::SettingsService* settings, const QString& oid) {
    const bool english = isEnglishUi(settings);
    const QString value = oid.trimmed().toLower();
    const auto label = [english](const char* ru, const char* en) {
        return QString::fromUtf8(english ? en : ru);
    };
    if (value.contains(QStringLiteral("sysdescr")) || value.endsWith(QStringLiteral(".1.0"))) return label("Описание устройства", "Device description");
    if (value.contains(QStringLiteral("sysobjectid")) || value.endsWith(QStringLiteral(".2.0"))) return label("Идентификатор модели", "Model identifier");
    if (value.contains(QStringLiteral("sysuptime")) || value.endsWith(QStringLiteral(".3.0"))) return label("Время работы", "Uptime");
    if (value.contains(QStringLiteral("syscontact")) || value.endsWith(QStringLiteral(".4.0"))) return label("Контакт", "Contact");
    if (value.contains(QStringLiteral("sysname")) || value.endsWith(QStringLiteral(".5.0"))) return label("Имя устройства", "Device name");
    if (value.contains(QStringLiteral("syslocation")) || value.endsWith(QStringLiteral(".6.0"))) return label("Расположение", "Location");
    if (value.contains(QStringLiteral("sysservices")) || value.endsWith(QStringLiteral(".7.0"))) return label("Сервисы", "Services");
    if (value.contains(QStringLiteral("ifdescr"))) return label("Имя интерфейса", "Interface name");
    if (value.contains(QStringLiteral("ifalias"))) return label("Псевдоним интерфейса", "Interface alias");
    if (value.contains(QStringLiteral("ifname"))) return label("Системное имя интерфейса", "System interface name");
    if (value.contains(QStringLiteral("ifadminstatus"))) return label("Административный статус", "Administrative status");
    if (value.contains(QStringLiteral("ifoperstatus"))) return label("Рабочий статус", "Operational status");
    if (value.contains(QStringLiteral("ifphysaddress"))) return label("MAC интерфейса", "Interface MAC");
    if (value.contains(QStringLiteral("ifspeed"))) return label("Скорость интерфейса", "Interface speed");
    if (value.contains(QStringLiteral("ifindex"))) return label("Индекс интерфейса", "Interface index");
    if (value.contains(QStringLiteral("ifnumber"))) return label("Количество интерфейсов", "Interface count");
    if (value.contains(QStringLiteral("iftype"))) return label("Тип интерфейса", "Interface type");
    if (value.contains(QStringLiteral("ifmtu"))) return label("MTU интерфейса", "Interface MTU");
    if (value.contains(QStringLiteral("iflastchange"))) return label("Последнее изменение интерфейса", "Last interface change");
    if (value.contains(QStringLiteral("ifinoctets"))) return label("Входящий трафик", "Inbound traffic");
    if (value.contains(QStringLiteral("ifinucastpkts"))) return label("Входящие unicast пакеты", "Inbound unicast packets");
    if (value.contains(QStringLiteral("ifinnucastpkts"))) return label("Входящие non-unicast пакеты", "Inbound non-unicast packets");
    if (value.contains(QStringLiteral("ifoutoctets"))) return label("Исходящий трафик", "Outbound traffic");
    if (value.contains(QStringLiteral("ifoutucastpkts"))) return label("Исходящие unicast пакеты", "Outbound unicast packets");
    if (value.contains(QStringLiteral("ifoutnucastpkts"))) return label("Исходящие non-unicast пакеты", "Outbound non-unicast packets");
    if (value.contains(QStringLiteral("hrsystemuptime"))) return label("Время работы хоста", "Host uptime");
    if (value.contains(QStringLiteral("hrmemorysize"))) return label("Объем памяти", "Memory size");
    const QString prettified = prettifySnmpObjectLabel(oid);
    if (english && prettified == QStringLiteral("Параметр устройства")) {
        return QStringLiteral("Device parameter");
    }
    return prettified;
}

QString snmpObjectDescription(const QString& oid) {
    static QHash<QString, QString> cache;
    const QString objectName = snmpSymbolicObjectName(oid);
    if (objectName.isEmpty()) {
        return {};
    }
    const auto cached = cache.constFind(objectName);
    if (cached != cache.constEnd()) {
        return cached.value();
    }

    const QString program = executableToolPath(QStringLiteral("snmptranslate"));
    if (program.isEmpty()) {
        cache.insert(objectName, QString());
        return {};
    }

    QProcess process;
    configureSnmpProcessEnvironment(&process, program);
    process.start(program, {QStringLiteral("-Td"), objectName});
    if (!process.waitForFinished(1200)) {
        process.kill();
        process.waitForFinished(100);
        cache.insert(objectName, QString());
        return {};
    }

    const QString output = QString::fromUtf8(process.readAllStandardOutput());
    static const QRegularExpression descriptionRe(
        QStringLiteral("DESCRIPTION\\s+\"([\\s\\S]*?)\"\\s*::="),
        QRegularExpression::DotMatchesEverythingOption
    );
    QString description;
    const auto match = descriptionRe.match(output);
    if (match.hasMatch()) {
        description = match.captured(1).simplified();
    }
    cache.insert(objectName, description);
    return description;
}

bool openPingInTerminal(const QString& ip) {
    if (ip.trimmed().isEmpty()) {
        return false;
    }
#ifdef Q_OS_MACOS
    return QProcess::startDetached(
        QStringLiteral("/usr/bin/osascript"),
        {
            QStringLiteral("-e"),
            QStringLiteral("tell application \"Terminal\" to activate"),
            QStringLiteral("-e"),
            QStringLiteral("tell application \"Terminal\" to do script \"ping %1\"").arg(ip),
        }
    );
#elif defined(Q_OS_WIN)
    const QString cmdPath = QDir::toNativeSeparators(qEnvironmentVariable("WINDIR", QStringLiteral("C:\\Windows")) + QStringLiteral("\\System32\\cmd.exe"));
    return QProcess::startDetached(
        QFileInfo::exists(cmdPath) ? cmdPath : QStringLiteral("cmd.exe"),
        {QStringLiteral("/k"), QStringLiteral("ping %1").arg(ip)}
    );
#else
    return QProcess::startDetached(
        QStringLiteral("x-terminal-emulator"),
        {QStringLiteral("-e"), QStringLiteral("sh"), QStringLiteral("-lc"), QStringLiteral("ping %1; exec sh").arg(ip)}
    );
#endif
}

QString localizedRuntimeStatus(const nt::SettingsService* settings, const QString& text) {
    if (!isEnglishUi(settings)) {
        return text;
    }

    if (text == QStringLiteral("Отключено")) {
        return QStringLiteral("Disconnected");
    }
    if (text == QStringLiteral("Закрыто")) {
        return QStringLiteral("Closed");
    }
    if (text == QStringLiteral("Доступ отклонен")) {
        return QStringLiteral("Access denied");
    }
    if (text == QStringLiteral("Подключение SSH...")) {
        return QStringLiteral("Connecting SSH...");
    }
    if (text == QStringLiteral("SSH завершился")) {
        return QStringLiteral("SSH exited");
    }
    if (text == QStringLiteral("SSH-клиент не найден. Установите OpenSSH, sshpass или plink.")) {
        return QStringLiteral("SSH client not found. Install OpenSSH, sshpass, or plink.");
    }
    if (text == QStringLiteral("Serial не подключен")) {
        return QStringLiteral("Serial is not connected");
    }
    if (text == QStringLiteral("Serial записал не все байты")) {
        return QStringLiteral("Serial wrote only part of the payload");
    }
    if (text == QStringLiteral("TCP не подключен")) {
        return QStringLiteral("TCP is not connected");
    }
    if (text == QStringLiteral("TCP timeout")) {
        return QStringLiteral("TCP timeout");
    }
    if (text == QStringLiteral("Telnet не подключен")) {
        return QStringLiteral("Telnet is not connected");
    }
    if (text == QStringLiteral("Telnet timeout")) {
        return QStringLiteral("Telnet timeout");
    }
    if (text == QStringLiteral("SSH не подключен")) {
        return QStringLiteral("SSH is not connected");
    }
    if (text == QStringLiteral("Не удалось разрешить UDP-хост")) {
        return QStringLiteral("Failed to resolve UDP host");
    }
    if (text.startsWith(QStringLiteral("UDP открыт :"))) {
        return QStringLiteral("UDP open :%1").arg(text.section(QLatin1Char(':'), 1));
    }
    if (text.startsWith(QStringLiteral("Подключено "))) {
        return QStringLiteral("Connected %1").arg(text.mid(QStringLiteral("Подключено ").size()));
    }
    return text;
}

QFont fixedFont(double pointSize = 10.5) {
    QFont font;
#ifdef Q_OS_MACOS
    font.setFamily(QStringLiteral("Menlo"));
#elif defined(Q_OS_WIN)
    font.setFamily(QStringLiteral("Consolas"));
#else
    font.setFamily(QStringLiteral("DejaVu Sans Mono"));
#endif
    font.setStyleHint(QFont::Monospace);
    font.setFixedPitch(true);
    font.setPointSizeF(pointSize);
    return font;
}

QColor terminalColorFromCode(int code) {
    switch (code) {
    case 30: return QColor("#0f1318");
    case 31: return QColor("#d85d5d");
    case 32: return QColor("#82c46c");
    case 33: return QColor("#d7bb62");
    case 34: return QColor("#6f9cd8");
    case 35: return QColor("#b184d7");
    case 36: return QColor("#68bfb5");
    case 37: return QColor("#d6dce4");
    case 90: return QColor("#5c6570");
    case 91: return QColor("#f27c7c");
    case 92: return QColor("#9ad988");
    case 93: return QColor("#f0d977");
    case 94: return QColor("#88b2ef");
    case 95: return QColor("#c8a0f3");
    case 96: return QColor("#82d9cf");
    case 97: return QColor("#f5f8fb");
    default: return QColor("#eef2f6");
    }
}

QColor terminalPresetColor(const QString& key) {
    const QString normalized = key.trimmed().toLower();
    if (normalized == QStringLiteral("green")) return QColor("#79df71");
    if (normalized == QStringLiteral("amber")) return QColor("#f0c86e");
    if (normalized == QStringLiteral("cyan")) return QColor("#7ed8e7");
    if (normalized == QStringLiteral("white")) return QColor("#eef2f6");
    return QColor("#8ff0c8");
}

QColor blendColor(const QColor& from, const QColor& to, qreal factor) {
    const qreal clamped = std::clamp(factor, 0.0, 1.0);
    return QColor(
        from.red() + static_cast<int>((to.red() - from.red()) * clamped),
        from.green() + static_cast<int>((to.green() - from.green()) * clamped),
        from.blue() + static_cast<int>((to.blue() - from.blue()) * clamped));
}

QTextCharFormat defaultTerminalFormat(const QColor& foreground = QColor("#8ff0c8")) {
    QTextCharFormat format;
    format.setFont(fixedFont());
    format.setForeground(foreground);
    format.setBackground(QColor("#0f1318"));
    format.setFontWeight(QFont::Normal);
    format.setFontUnderline(false);
    return format;
}

void applyTerminalSgr(const QList<int>& codes, QTextCharFormat& format, const QTextCharFormat& baseFormat) {
    if (codes.isEmpty()) {
        format = baseFormat;
        return;
    }
    for (const int code : codes) {
        if (code == 0) {
            format = baseFormat;
        } else if (code == 1) {
            format.setFontWeight(QFont::Bold);
        } else if (code == 22) {
            format.setFontWeight(QFont::Normal);
        } else if (code == 4) {
            format.setFontUnderline(true);
        } else if (code == 24) {
            format.setFontUnderline(false);
        } else if (code == 39) {
            format.setForeground(baseFormat.foreground());
        } else if (code == 49) {
            format.setBackground(baseFormat.background());
        } else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
            format.setForeground(terminalColorFromCode(code));
        } else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) {
            const int fgCode = code >= 100 ? code - 10 : code - 10;
            format.setBackground(terminalColorFromCode(fgCode));
        }
    }
}

QColor httpMethodColor(const QString& method) {
    const QString upper = method.trimmed().toUpper();
    if (upper == QStringLiteral("GET")) return QColor("#5db0ff");
    if (upper == QStringLiteral("POST")) return QColor("#6fd27f");
    if (upper == QStringLiteral("PUT")) return QColor("#f2c36a");
    if (upper == QStringLiteral("PATCH")) return QColor("#cb8cf2");
    if (upper == QStringLiteral("DELETE")) return QColor("#ef7b7b");
    return QColor("#d9e1eb");
}

QColor httpStatusColor(int statusCode, bool hasError) {
    if (hasError || statusCode >= 500 || statusCode == 0) {
        return QColor("#ef7b7b");
    }
    if (statusCode >= 200 && statusCode < 300) {
        return QColor("#6fd27f");
    }
    return QColor("#f2c36a");
}

QString scanSnapshotSummary(const nt::ScanRecord& row) {
    const auto normalize = [](const QString& value, const QString& fallback) {
        return value.trimmed().isEmpty() || value == QStringLiteral("-") ? fallback : value;
    };
    return QStringLiteral("%1 | %2 | %3")
        .arg(normalize(row.mac, QStringLiteral("-")))
        .arg(normalize(row.vendor, QStringLiteral("unknown vendor")))
        .arg(normalize(row.port, QStringLiteral("-")));
}

void appendConsole(QPlainTextEdit* box, const QString& text) {
    if (box == nullptr || text.isEmpty()) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText(text);
    if (!text.endsWith(QLatin1Char('\n'))) {
        cursor.insertText(QStringLiteral("\n"));
    }
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

quint32 ipToInt(const QString& ip) {
    const auto address = QHostAddress(ip);
    return address.protocol() == QAbstractSocket::IPv4Protocol ? address.toIPv4Address() : 0u;
}

int insertionRowForIp(QTableWidget* table, const QString& ip, bool ascending) {
    if (table == nullptr) {
        return 0;
    }
    const quint32 target = ipToInt(ip);
    for (int row = 0; row < table->rowCount(); ++row) {
        const auto* item = table->item(row, 0);
        if (item == nullptr) {
            return row;
        }
        const quint32 current = ipToInt(scanIpFromItem(item));
        if ((ascending && current > target) || (!ascending && current < target)) {
            return row;
        }
    }
    return table->rowCount();
}

QPair<QString, QString> rangeFromIpAndPrefix(const QString& ip, int prefixLength) {
    if (prefixLength <= 0 || prefixLength > 32) {
        return {ip, ip};
    }

    const quint32 value = ipToInt(ip);
    if (value == 0u) {
        return {ip, ip};
    }

    const quint32 mask = prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - prefixLength));
    const quint32 network = value & mask;
    const quint32 broadcast = network | (~mask);
    if (broadcast <= network + 1u) {
        return {QHostAddress(value).toString(), QHostAddress(value).toString()};
    }
    return {QHostAddress(network + 1u).toString(), QHostAddress(broadcast - 1u).toString()};
}

QIcon statusOrb(nt::HostStatus status) {
    QColor outer("#c93d27");
    QColor center("#ff947f");
    if (status == nt::HostStatus::Online) {
        outer = QColor("#2f9728");
        center = QColor("#93ef70");
    } else if (status == nt::HostStatus::Unknown) {
        outer = QColor("#1f42af");
        center = QColor("#7ca5ff");
    }

    QPixmap pixmap(26, 26);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(QPen(QColor(0, 0, 0, 120), 1.1));
    QRadialGradient gradient(10, 9, 12, 8, 7);
    gradient.setColorAt(0.0, QColor("#ffffff"));
    gradient.setColorAt(0.18, center);
    gradient.setColorAt(1.0, outer);
    painter.setBrush(gradient);
    painter.drawEllipse(2, 2, 21, 21);
    return QIcon(pixmap);
}

QString fallbackCell(const QString& value, const QString& fallback) {
    return value.trimmed().isEmpty() || value == QStringLiteral("-") ? fallback : value;
}

QString displayCellValue(const nt::SettingsService* settings, const QString& value, const QString& fallback) {
    QString display = fallbackCell(value, fallback);
    if (display == QStringLiteral("-")) {
        display = localizedMissingText(settings);
    }
    return display;
}

bool isUnknownVendorText(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized == QStringLiteral("?")
        || normalized == QStringLiteral("unknown vendor");
}

bool isMissingScanValue(const QString& value) {
    return isUnknownVendorText(value);
}

bool isWeakScanType(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return isMissingScanValue(normalized)
        || normalized == QStringLiteral("icmp")
        || normalized == QStringLiteral("udp")
        || normalized == QStringLiteral("arp")
        || normalized == QStringLiteral("mdns")
        || normalized == QStringLiteral("ssdp")
        || normalized == QStringLiteral("link");
}

bool isValidGatewayText(const QString& value) {
    const auto address = QHostAddress(value.trimmed());
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    const quint32 ip = address.toIPv4Address();
    const quint8 first = static_cast<quint8>((ip >> 24) & 0xff);
    const quint8 last = static_cast<quint8>(ip & 0xff);
    return ip != 0
        && ip != 0xffffffffu
        && first != 0
        && first != 127
        && first < 224
        && !(first == 169 && static_cast<quint8>((ip >> 16) & 0xff) == 254)
        && last != 0
        && last != 255;
}

void mergeScanDisplayFields(nt::ScanRecord& target, const nt::ScanRecord& source) {
    if (target.ip.isEmpty() || source.ip.isEmpty() || target.ip != source.ip) {
        return;
    }

    if ((target.mac.trimmed().isEmpty() || target.mac == QStringLiteral("-"))
        && !source.mac.trimmed().isEmpty()
        && source.mac != QStringLiteral("-")) {
        target.mac = source.mac;
    }
    if (isMissingScanValue(target.pingDisplay) && !isMissingScanValue(source.pingDisplay)) {
        target.pingDisplay = source.pingDisplay;
        if (source.status == nt::HostStatus::Online) {
            target.status = nt::HostStatus::Online;
        }
        if (isMissingScanValue(target.speed) && !isMissingScanValue(source.speed)) {
            target.speed = source.speed;
        }
        if (isWeakScanType(target.typeHint) && !isWeakScanType(source.typeHint)) {
            target.typeHint = source.typeHint;
        }
    } else if (target.status != nt::HostStatus::Online && source.status == nt::HostStatus::Online) {
        target.status = nt::HostStatus::Online;
    }

    if (isMissingScanValue(target.portsDisplay) && !isMissingScanValue(source.portsDisplay)) {
        target.portsDisplay = source.portsDisplay;
    }
    if (isMissingScanValue(target.port) && !isMissingScanValue(source.port)) {
        target.port = source.port;
    }
    if (isMissingScanValue(target.webDetect) && !isMissingScanValue(source.webDetect)) {
        target.webDetect = source.webDetect;
    }
    if (isWeakScanType(target.typeHint) && !isWeakScanType(source.typeHint)) {
        target.typeHint = source.typeHint;
    }

    if (isUnknownVendorText(target.hostName) && !isUnknownVendorText(source.hostName)) {
        target.hostName = source.hostName;
    }
    if (!isUnknownVendorText(target.hostName)) {
        target.vendor = target.hostName;
    } else if (isUnknownVendorText(target.vendor) && !isUnknownVendorText(source.vendor)) {
        target.vendor = source.vendor;
    }
    if (isMissingScanValue(target.name) && !isMissingScanValue(source.name)) {
        target.name = source.name;
    }
    if (!isValidGatewayText(target.gateway)) {
        target.gateway = QStringLiteral("-");
    }
    if (!isValidGatewayText(target.gateway) && isValidGatewayText(source.gateway)) {
        target.gateway = source.gateway;
    }
    if (isMissingScanValue(target.mask) && !isMissingScanValue(source.mask)) {
        target.mask = source.mask;
    }
}

class SettingsDialog final : public QDialog {
public:
    SettingsDialog(nt::SettingsService* settings, QWidget* parent = nullptr)
        : QDialog(parent)
        , m_settings(settings) {
        const QString language = settings != nullptr ? settings->language() : QStringLiteral("ru");
        setWindowTitle(uiText(language, "Настройки", "Settings"));
        setModal(true);
        resize(560, 280);

        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(10, 8, 10, 8);
        root->setSpacing(4);
        auto* scanForm = new QFormLayout();
        scanForm->setContentsMargins(0, 0, 0, 0);
        scanForm->setHorizontalSpacing(8);
        scanForm->setVerticalSpacing(4);

        m_workersSpin = new QSpinBox(this);
        m_workersSpin->setRange(8, 128);
        m_workersSpin->setValue(settings->scanWorkers());
        scanForm->addRow(uiText(language, "Потоки сканирования", "Scan workers"), m_workersSpin);

        m_scanProfileCombo = new QComboBox(this);
        m_scanProfileCombo->addItem(uiText(language, "Быстро", "Fast"), QStringLiteral("fast"));
        m_scanProfileCombo->addItem(uiText(language, "Баланс", "Balanced"), QStringLiteral("balanced"));
        m_scanProfileCombo->addItem(uiText(language, "Надежно / слабая сеть", "Reliable / weak network"), QStringLiteral("reliable"));
        m_scanProfileCombo->setCurrentIndex(qMax(0, m_scanProfileCombo->findData(settings->scanProfile())));
        scanForm->addRow(uiText(language, "Профиль сканирования", "Scan profile"), m_scanProfileCombo);

        m_autoScanIntervalSpin = new QSpinBox(this);
        m_autoScanIntervalSpin->setRange(5, 3600);
        m_autoScanIntervalSpin->setValue(qMax(5, settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)));
        m_autoScanIntervalSpin->setSuffix(uiText(language, " сек", " sec"));
        scanForm->addRow(uiText(language, "Интервал автосканa", "Auto scan interval"), m_autoScanIntervalSpin);

        root->addLayout(scanForm);

        m_autoWorkersCheck = new QCheckBox(uiText(language, "Авто потоки", "Auto workers"), this);
        m_autoWorkersCheck->setChecked(settings->value(QStringLiteral("scan_auto_workers"), true).toBool(true));
        m_backgroundRefreshCheck = new QCheckBox(uiText(language, "Фоновое обновление", "Background refresh"), this);
        m_backgroundRefreshCheck->setChecked(settings->value(QStringLiteral("scan_background_refresh"), false).toBool(false));
        m_backgroundRefreshCheck->setToolTip(uiText(
            language,
            "После обычного скана тихо обновляет текущую таблицу: пинг, имена, порты и ушедшие адреса.",
            "After a normal scan, quietly updates the current table: ping, names, ports, and departed hosts."
        ));
        m_scanOnStartupCheck = new QCheckBox(uiText(language, "Автоскан при запуске", "Scan on startup"), this);
        m_scanOnStartupCheck->setChecked(settings->value(QStringLiteral("scan_on_startup"), false).toBool(false));
        m_routedScanCheck = new QCheckBox(uiText(language, "Scan routed ranges", "Scan routed ranges"), this);
        m_routedScanCheck->setChecked(settings->value(QStringLiteral("scan_routed_ranges"), false).toBool(false));
        m_routedScanCheck->setToolTip(uiText(
            language,
            "Allow scanning manually entered routed ranges outside the current adapter subnet.",
            "Allow scanning manually entered routed ranges outside the current adapter subnet."
        ));

        auto refreshAutoWorkersState = [this, language]() {
            const int workers = autoScanWorkerCountForProfile(m_scanProfileCombo != nullptr ? m_scanProfileCombo->currentData().toString() : QStringLiteral("balanced"));
            if (m_autoWorkersCheck != nullptr) {
                m_autoWorkersCheck->setToolTip(uiText(language, "Авто режим выберет %1 потоков для текущего профиля.", "Auto mode will use %1 workers for the current profile.").arg(workers));
            }
            if (m_workersSpin != nullptr && m_autoWorkersCheck != nullptr) {
                m_workersSpin->setEnabled(!m_autoWorkersCheck->isChecked());
            }
        };
        connect(m_autoWorkersCheck, &QCheckBox::toggled, this, [refreshAutoWorkersState](bool) {
            refreshAutoWorkersState();
        });
        connect(m_scanProfileCombo, &QComboBox::currentIndexChanged, this, [refreshAutoWorkersState](int) {
            refreshAutoWorkersState();
        });
        refreshAutoWorkersState();

        auto* openLogsButton = new QPushButton(QStringLiteral("open logs"), this);
        openLogsButton->setObjectName(QStringLiteral("textLinkButton"));
        openLogsButton->setFlat(true);
        openLogsButton->setCursor(Qt::PointingHandCursor);
        openLogsButton->setToolTip(uiText(language, "Открыть лог последнего скана", "Open last scan log"));
        connect(openLogsButton, &QPushButton::clicked, this, []() {
            openIpScanLogFile();
        });

        auto* checks = new QHBoxLayout();
        checks->setContentsMargins(0, 0, 0, 0);
        checks->setSpacing(10);
        checks->addWidget(m_autoWorkersCheck);
        checks->addWidget(m_backgroundRefreshCheck);
        checks->addWidget(m_scanOnStartupCheck);
        checks->addWidget(m_routedScanCheck);
        checks->addStretch(1);
        checks->addWidget(openLogsButton);
        root->addLayout(checks);

        auto* uiForm = new QFormLayout();
        m_themeCombo = new QComboBox(this);
        m_themeCombo->addItem(uiText(language, "Темная", "Dark"), QStringLiteral("dark"));
        m_themeCombo->addItem(uiText(language, "Светлая", "Light"), QStringLiteral("light"));
        m_themeCombo->setCurrentIndex(qMax(0, m_themeCombo->findData(settings->theme())));
        uiForm->addRow(uiText(language, "Тема", "Theme"), m_themeCombo);

        m_languageCombo = new QComboBox(this);
        m_languageCombo->addItem(uiText(language, "Русский", "Russian"), QStringLiteral("ru"));
        m_languageCombo->addItem(QStringLiteral("English"), QStringLiteral("en"));
        m_languageCombo->setCurrentIndex(qMax(0, m_languageCombo->findData(settings->language())));
        uiForm->addRow(uiText(language, "Язык", "Language"), m_languageCombo);

        m_terminalColorCombo = new QComboBox(this);
        m_terminalColorCombo->addItem(QStringLiteral("Mint"), QStringLiteral("mint"));
        m_terminalColorCombo->addItem(QStringLiteral("Green"), QStringLiteral("green"));
        m_terminalColorCombo->addItem(QStringLiteral("Amber"), QStringLiteral("amber"));
        m_terminalColorCombo->addItem(QStringLiteral("Cyan"), QStringLiteral("cyan"));
        m_terminalColorCombo->addItem(QStringLiteral("White"), QStringLiteral("white"));
        m_terminalColorCombo->setCurrentIndex(qMax(0, m_terminalColorCombo->findData(settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint")))));
        uiForm->addRow(uiText(language, "SSH / Telnet цвет", "SSH / Telnet color"), m_terminalColorCombo);
        root->addLayout(uiForm);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        root->addWidget(buttons);

        connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
            m_settings->setValue(QStringLiteral("scan_workers"), m_workersSpin->value());
            m_settings->setValue(QStringLiteral("scan_auto_workers"), m_autoWorkersCheck->isChecked());
            m_settings->setValue(QStringLiteral("scan_profile"), m_scanProfileCombo->currentData().toString());
            m_settings->setValue(QStringLiteral("scan_profile_user_selected"), true);
            m_settings->setValue(QStringLiteral("scan_background_refresh"), m_backgroundRefreshCheck->isChecked());
            m_settings->setValue(QStringLiteral("scan_on_startup"), m_scanOnStartupCheck->isChecked());
            m_settings->setValue(QStringLiteral("scan_routed_ranges"), m_routedScanCheck->isChecked());
            m_settings->setValue(QStringLiteral("auto_scan_interval_sec"), m_autoScanIntervalSpin->value());
            m_settings->setValue(QStringLiteral("theme"), m_themeCombo->currentData().toString());
            m_settings->setValue(QStringLiteral("language"), m_languageCombo->currentData().toString());
            m_settings->setValue(QStringLiteral("terminal_text_color"), m_terminalColorCombo->currentData().toString());
            m_settings->save();
            accept();
        });
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    }

private:
    nt::SettingsService* m_settings {nullptr};
    QSpinBox* m_workersSpin {nullptr};
    QComboBox* m_scanProfileCombo {nullptr};
    QCheckBox* m_autoWorkersCheck {nullptr};
    QCheckBox* m_backgroundRefreshCheck {nullptr};
    QCheckBox* m_scanOnStartupCheck {nullptr};
    QCheckBox* m_routedScanCheck {nullptr};
    QSpinBox* m_autoScanIntervalSpin {nullptr};
    QComboBox* m_themeCombo {nullptr};
    QComboBox* m_languageCombo {nullptr};
    QComboBox* m_terminalColorCombo {nullptr};
};

} // namespace

// Keep the local helper namespace above in one translation unit, while the
// MainWindow method bodies live in focused implementation fragments.
#include "mainwindow/MainWindowLifecycle.inc"
#include "mainwindow/MainWindowPages.inc"
#include "mainwindow/MainWindowScan.inc"
#include "mainwindow/MainWindowTransports.inc"
#include "mainwindow/MainWindowSnmp.inc"
