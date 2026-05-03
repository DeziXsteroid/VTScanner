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
#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractSocket>
#include <QBrush>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QClipboard>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QEventLoop>
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
#include <QProcess>
#include <QPushButton>
#include <QRadialGradient>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyleFactory>
#include <QTableWidgetSelectionRange>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QSerialPortInfo>
#include <QTabWidget>
#include <QTimer>
#include <QTextCursor>
#include <QTextEdit>
#include <QUrl>
#include <QVariantAnimation>
#include <QVariant>
#include <QVBoxLayout>

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

QString uiText(const QString& language, const char* ru, const char* en) {
    return QString::fromUtf8(language == QStringLiteral("en") ? en : ru);
}

QString uiText(const nt::SettingsService* settings, const char* ru, const char* en) {
    return uiText(settings != nullptr ? settings->language() : QStringLiteral("ru"), ru, en);
}

bool isEnglishUi(const nt::SettingsService* settings) {
    return settings != nullptr && settings->language() == QStringLiteral("en");
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

QString localizedScanFinishedText(const nt::SettingsService* settings, int durationMs) {
    return isEnglishUi(settings)
        ? QStringLiteral("Scan finished in %1 s").arg(durationMs / 1000.0, 0, 'f', 2)
        : QStringLiteral("Сканирование завершено за %1 c").arg(durationMs / 1000.0, 0, 'f', 2);
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
    if (!isNewHost) {
        return baseText;
    }
    return baseText == localizedMissingText(settings)
        ? comparisonBadgeText()
        : QStringLiteral("%1 %2").arg(comparisonBadgeText(), baseText);
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

    QProcess process;
    process.start(QStringLiteral("/usr/bin/snmptranslate"), {QStringLiteral("-Td"), objectName});
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
    return QProcess::startDetached(
        QStringLiteral("cmd.exe"),
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
    if (text == QStringLiteral("TCP не подключен")) {
        return QStringLiteral("TCP is not connected");
    }
    if (text == QStringLiteral("Telnet не подключен")) {
        return QStringLiteral("Telnet is not connected");
    }
    if (text == QStringLiteral("SSH не подключен")) {
        return QStringLiteral("SSH is not connected");
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
        const quint32 current = ipToInt(item->text());
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
        auto* form = new QFormLayout();

        m_workersSpin = new QSpinBox(this);
        m_workersSpin->setRange(8, 96);
        m_workersSpin->setValue(settings->scanWorkers());
        form->addRow(uiText(language, "Потоки сканирования", "Scan workers"), m_workersSpin);

        m_scanOnStartupCheck = new QCheckBox(uiText(language, "Включить", "Enable"), this);
        m_scanOnStartupCheck->setChecked(settings->value(QStringLiteral("scan_on_startup"), true).toBool(true));
        form->addRow(uiText(language, "Автоскан при запуске", "Scan on startup"), m_scanOnStartupCheck);

        m_autoScanIntervalSpin = new QSpinBox(this);
        m_autoScanIntervalSpin->setRange(5, 3600);
        m_autoScanIntervalSpin->setValue(qMax(5, settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)));
        m_autoScanIntervalSpin->setSuffix(uiText(language, " сек", " sec"));
        form->addRow(uiText(language, "Интервал автосканa", "Auto scan interval"), m_autoScanIntervalSpin);

        m_themeCombo = new QComboBox(this);
        m_themeCombo->addItem(uiText(language, "Темная", "Dark"), QStringLiteral("dark"));
        m_themeCombo->addItem(uiText(language, "Светлая", "Light"), QStringLiteral("light"));
        m_themeCombo->setCurrentIndex(qMax(0, m_themeCombo->findData(settings->theme())));
        form->addRow(uiText(language, "Тема", "Theme"), m_themeCombo);

        m_languageCombo = new QComboBox(this);
        m_languageCombo->addItem(uiText(language, "Русский", "Russian"), QStringLiteral("ru"));
        m_languageCombo->addItem(QStringLiteral("English"), QStringLiteral("en"));
        m_languageCombo->setCurrentIndex(qMax(0, m_languageCombo->findData(settings->language())));
        form->addRow(uiText(language, "Язык", "Language"), m_languageCombo);

        m_terminalColorCombo = new QComboBox(this);
        m_terminalColorCombo->addItem(QStringLiteral("Mint"), QStringLiteral("mint"));
        m_terminalColorCombo->addItem(QStringLiteral("Green"), QStringLiteral("green"));
        m_terminalColorCombo->addItem(QStringLiteral("Amber"), QStringLiteral("amber"));
        m_terminalColorCombo->addItem(QStringLiteral("Cyan"), QStringLiteral("cyan"));
        m_terminalColorCombo->addItem(QStringLiteral("White"), QStringLiteral("white"));
        m_terminalColorCombo->setCurrentIndex(qMax(0, m_terminalColorCombo->findData(settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint")))));
        form->addRow(uiText(language, "SSH / Telnet цвет", "SSH / Telnet color"), m_terminalColorCombo);

        root->addLayout(form);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        root->addWidget(buttons);

        connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
            m_settings->setValue(QStringLiteral("scan_workers"), m_workersSpin->value());
            m_settings->setValue(QStringLiteral("scan_on_startup"), m_scanOnStartupCheck->isChecked());
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
    QCheckBox* m_scanOnStartupCheck {nullptr};
    QSpinBox* m_autoScanIntervalSpin {nullptr};
    QComboBox* m_themeCombo {nullptr};
    QComboBox* m_languageCombo {nullptr};
    QComboBox* m_terminalColorCombo {nullptr};
};

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_settings(new nt::SettingsService(this))
    , m_vendorDb(new nt::VendorDbService(this))
    , m_snapshots(new nt::SnapshotService(this))
    , m_scanner(new nt::NetworkScanService(m_vendorDb, this))
    , m_http(new nt::HttpRequestService(this))
    , m_serialSession(new nt::SerialSession(this))
    , m_sshSession(new nt::SshProcessSession(this))
    , m_tcpSession(new nt::TcpClientSession(this))
    , m_telnetSession(new nt::TelnetSession(this))
    , m_udpSession(new nt::UdpSocketSession(this)) {
    m_settings->load();
    const bool compactWindowV1Applied = m_settings->value(QStringLiteral("window_compact_v1"), false).toBool(false);
    if (!compactWindowV1Applied) {
        QJsonObject windowSection = m_settings->section(QStringLiteral("window"));
        const int currentHeight = windowSection.value(QStringLiteral("height")).toInt(490);
        windowSection.insert(QStringLiteral("height"), qBound(445, currentHeight - 12, 528));
        m_settings->setSection(QStringLiteral("window"), windowSection);
        m_settings->setValue(QStringLiteral("window_compact_v1"), true);
        m_settings->save();
    }
    const bool compactWindowV2Applied = m_settings->value(QStringLiteral("window_compact_v2"), false).toBool(false);
    if (!compactWindowV2Applied) {
        QJsonObject windowSection = m_settings->section(QStringLiteral("window"));
        const int currentWidth = windowSection.value(QStringLiteral("width")).toInt(920);
        const int currentHeight = windowSection.value(QStringLiteral("height")).toInt(478);
        windowSection.insert(QStringLiteral("width"), qBound(840, currentWidth - 90, 874));
        windowSection.insert(QStringLiteral("height"), qBound(438, currentHeight - 8, 470));
        m_settings->setSection(QStringLiteral("window"), windowSection);
        m_settings->setValue(QStringLiteral("window_compact_v2"), true);
        m_settings->save();
    }
    const bool snmpScopeV2Applied = m_settings->value(QStringLiteral("snmp_scope_v2"), false).toBool(false);
    if (!snmpScopeV2Applied) {
        QJsonObject snmpSection = m_settings->section(QStringLiteral("snmp"));
        const QString currentBaseOid = snmpSection.value(QStringLiteral("base_oid")).toString(QStringLiteral(".1")).trimmed();
        if (currentBaseOid.isEmpty()
            || currentBaseOid == QStringLiteral(".1.3.6.1.2.1.1")
            || currentBaseOid == QStringLiteral(".1.3.6.1.2.1")) {
            snmpSection.insert(QStringLiteral("base_oid"), QStringLiteral(".1"));
            m_settings->setSection(QStringLiteral("snmp"), snmpSection);
        }
        m_settings->setValue(QStringLiteral("snmp_scope_v2"), true);
        m_settings->save();
    }
    const bool compactWindowV3Applied = m_settings->value(QStringLiteral("window_compact_v3"), false).toBool(false);
    if (!compactWindowV3Applied) {
        QJsonObject windowSection = m_settings->section(QStringLiteral("window"));
        const int currentHeight = windowSection.value(QStringLiteral("height")).toInt(470);
        windowSection.insert(QStringLiteral("height"), qBound(436, currentHeight - 4, 466));
        m_settings->setSection(QStringLiteral("window"), windowSection);
        m_settings->setValue(QStringLiteral("window_compact_v3"), true);
        m_settings->save();
    }
    const bool compactWindowV4Applied = m_settings->value(QStringLiteral("window_compact_v4"), false).toBool(false);
    if (!compactWindowV4Applied) {
        QJsonObject windowSection = m_settings->section(QStringLiteral("window"));
        const int currentHeight = windowSection.value(QStringLiteral("height")).toInt(466);
        windowSection.insert(QStringLiteral("height"), qBound(440, currentHeight + 6, 472));
        m_settings->setSection(QStringLiteral("window"), windowSection);
        m_settings->setValue(QStringLiteral("window_compact_v4"), true);
        m_settings->save();
    }
    const bool snmpDefaultsV1Applied = m_settings->value(QStringLiteral("snmp_defaults_v1"), false).toBool(false);
    if (!snmpDefaultsV1Applied) {
        QJsonObject snmpSection = m_settings->section(QStringLiteral("snmp"));
        const QString currentHost = snmpSection.value(QStringLiteral("host")).toString().trimmed();
        if (currentHost == QStringLiteral("127.0.0.1") || currentHost == QStringLiteral("192.168.1.185")) {
            snmpSection.insert(QStringLiteral("host"), QString());
            m_settings->setSection(QStringLiteral("snmp"), snmpSection);
        }
        m_settings->setValue(QStringLiteral("snmp_defaults_v1"), true);
        m_settings->save();
    }
    refreshTerminalFormats();
    m_vendorDb->ensureReady(false);
    m_scanAutoScanTimer = new QTimer(this);
    m_scanAutoScanTimer->setSingleShot(false);
    m_scanAutoScanTimer->setInterval(qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)) * 1000);

    qRegisterMetaType<nt::ScanRecord>("nt::ScanRecord");
    qRegisterMetaType<QList<nt::ScanRecord>>("QList<nt::ScanRecord>");
    qRegisterMetaType<nt::HttpResponse>("nt::HttpResponse");

    applyDarkPalette();
    applyStyleSheet();
    buildUi();

    setWindowTitle(localizedWindowTitle(m_settings));
    resize(m_settings->initialWindowSize());
    setMinimumSize(840, 440);
    statusBar()->hide();
    updateScanFooter(localizedScanIdleText(m_settings));

    connect(m_scanAutoScanTimer, &QTimer::timeout, this, [this]() {
        if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked() && !m_scanner->isRunning()) {
            startScan();
        }
    });
    const bool autoScanEnabled = m_settings->value(QStringLiteral("auto_scan_enabled"), false).toBool(false);
    const bool scanOnStartup = m_settings->value(QStringLiteral("scan_on_startup"), true).toBool(true);
    if (autoScanEnabled || scanOnStartup) {
        QTimer::singleShot(250, this, [this]() {
            if (!m_scanner->isRunning()) {
                startScan();
            }
        });
    }

    connect(m_scanner, &nt::NetworkScanService::scanStarted, this, [this]() {
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setText(uiText(m_settings, "■ Стоп", "■ Stop"));
            m_scanStartButton->setEnabled(true);
        }
        if (m_scanStopButton != nullptr) {
            m_scanStopButton->setEnabled(true);
        }
        updateScanFooter(uiText(m_settings, "Сканирование...", "Scanning..."));
    });
    connect(m_scanner, &nt::NetworkScanService::recordReady, this, &MainWindow::appendScanRecord);
    connect(m_scanner, &nt::NetworkScanService::scanFinished, this, &MainWindow::finalizeScan);
    connect(m_scanner, &nt::NetworkScanService::scanFailed, this, [this](const QString& errorText) {
        QMessageBox::warning(this, uiText(m_settings, "Сканер IP", "IP Scanner"), localizedRuntimeStatus(m_settings, errorText));
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setEnabled(true);
            m_scanStartButton->setText(uiText(m_settings, "▶ Старт", "▶ Start"));
        }
        if (m_scanStopButton != nullptr) {
            m_scanStopButton->setEnabled(false);
        }
        if (m_scanFooterThreadsLabel != nullptr) {
            m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, m_scanRows.size()));
        }
        updateScanFooter(localizedScanIdleText(m_settings));
    });

    connect(m_http, &nt::HttpRequestService::finished, this, [this](const nt::HttpResponse& response) {
        if (m_requestResponseEdit == nullptr) {
            return;
        }
        QTextCursor cursor(m_requestResponseEdit->document());
        cursor.movePosition(QTextCursor::End);

        QTextCharFormat statusFormat;
        statusFormat.setFont(fixedFont());
        statusFormat.setFontWeight(QFont::Bold);
        statusFormat.setForeground(httpStatusColor(response.statusCode, !response.errorText.isEmpty()));

        QTextCharFormat textFormat;
        textFormat.setFont(fixedFont());
        textFormat.setForeground(isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6"));

        auto setHttpBlockAlignment = [&cursor](Qt::Alignment alignment) {
            QTextBlockFormat blockFormat = cursor.blockFormat();
            blockFormat.setAlignment(alignment);
            cursor.setBlockFormat(blockFormat);
        };

        const QString statusText = response.errorText.isEmpty()
            ? QStringLiteral("HTTP %1 %2").arg(response.statusCode).arg(response.reasonPhrase.trimmed())
            : QStringLiteral("ERROR %1").arg(response.errorText);
        setHttpBlockAlignment(Qt::AlignHCenter);
        cursor.insertText(localizedRequestStatusDivider(), textFormat);
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignLeft);
        cursor.insertText(statusText.trimmed(), statusFormat);
        cursor.insertBlock();
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignHCenter);
        cursor.insertText(localizedRequestBodyDivider(), textFormat);
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignLeft);

        QString text;
        if (!response.errorText.isEmpty()) {
            text = localizedRuntimeStatus(m_settings, response.errorText);
        } else {
            const auto parsed = QJsonDocument::fromJson(response.body);
            if (!parsed.isNull()) {
                text = QString::fromUtf8(parsed.toJson(QJsonDocument::Indented));
            } else {
                text = QString::fromUtf8(response.body);
            }
        }
        if (text.trimmed().isEmpty()) {
            text = uiText(m_settings, "(пустой ответ)", "(empty response)");
        }
        cursor.insertText(text, textFormat);
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignHCenter);
        cursor.insertText(localizedRequestEndDivider(), textFormat);
        cursor.insertBlock();
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignLeft);
        m_requestResponseEdit->setTextCursor(cursor);
        m_requestResponseEdit->ensureCursorVisible();
    });

    connect(m_serialSession, &nt::SerialSession::dataReceived, this, [this](const QByteArray& bytes) {
        appendTrafficEntry(
            m_serialWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_serialWidgets.hexCheck != nullptr && m_serialWidgets.hexCheck->isChecked())
        );
    });
    connect(m_serialSession, &nt::SerialSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_serialSession, &nt::SerialSession::connectedChanged, this, [this](bool connected) {
        if (m_serialWidgets.connectButton != nullptr) {
            m_serialWidgets.connectButton->setText(localizedConnectText(m_settings, connected));
        }
    });

    connect(m_tcpSession, &nt::TcpClientSession::dataReceived, this, [this](const QByteArray& bytes) {
        appendTrafficEntry(
            m_tcpWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_tcpWidgets.hexCheck != nullptr && m_tcpWidgets.hexCheck->isChecked())
        );
    });
    connect(m_tcpSession, &nt::TcpClientSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_tcpSession, &nt::TcpClientSession::connectedChanged, this, [this](bool connected) {
        if (m_tcpWidgets.connectButton != nullptr) {
            m_tcpWidgets.connectButton->setText(localizedConnectText(m_settings, connected));
        }
    });

    connect(m_udpSession, &nt::UdpSocketSession::datagramReceived, this, [this](const QString& endpoint, const QByteArray& bytes) {
        appendTrafficEntry(
            m_udpWidgets.outputBox,
            QColor("#66a8ff"),
            QStringLiteral("RX"),
            displayBytes(bytes, m_udpWidgets.hexCheck != nullptr && m_udpWidgets.hexCheck->isChecked()),
            endpoint
        );
    });
    connect(m_udpSession, &nt::UdpSocketSession::stateChanged, this, [this](const QString& text) {
        statusBar()->showMessage(text, 3000);
    });
    connect(m_udpSession, &nt::UdpSocketSession::connectedChanged, this, [this](bool open) {
        if (m_udpWidgets.connectButton != nullptr) {
            m_udpWidgets.connectButton->setText(localizedUdpToggleText(m_settings, open));
        }
    });

    connect(m_sshSession, &nt::SshProcessSession::outputReady, this, [this](const QString& text) {
        appendSessionTerminalOutput(m_sshWidgets.outputBox, text);
    });
    connect(m_sshSession, &nt::SshProcessSession::stateChanged, this, [this](const QString& text) {
        if (m_sshWidgets.statusLabel != nullptr) {
            m_sshWidgets.statusLabel->setText(localizedRuntimeStatus(m_settings, text));
        }
    });
    connect(m_sshSession, &nt::SshProcessSession::connectedChanged, this, [this](bool connected) {
        if (m_sshWidgets.connectButton != nullptr) {
            m_sshWidgets.connectButton->setText(localizedConnectText(m_settings, connected));
        }
    });

    connect(m_telnetSession, &nt::TelnetSession::outputReady, this, [this](const QString& text) {
        appendSessionTerminalOutput(m_telnetWidgets.outputBox, text);
    });
    connect(m_telnetSession, &nt::TelnetSession::stateChanged, this, [this](const QString& text) {
        if (m_telnetWidgets.statusLabel != nullptr) {
            m_telnetWidgets.statusLabel->setText(localizedRuntimeStatus(m_settings, text));
        }
    });
    connect(m_telnetSession, &nt::TelnetSession::connectedChanged, this, [this](bool connected) {
        if (m_telnetWidgets.connectButton != nullptr) {
            m_telnetWidgets.connectButton->setText(localizedConnectText(m_settings, connected));
        }
    });
}

MainWindow::~MainWindow() = default;

void MainWindow::closeEvent(QCloseEvent* event) {
    m_settings->setSection(QStringLiteral("window"), QJsonObject{
        {QStringLiteral("width"), width()},
        {QStringLiteral("height"), height()},
    });
    m_settings->save();
    m_scanner->cancel();
    m_sshSession->close();
    m_telnetSession->close();
    QMainWindow::closeEvent(event);
}

bool MainWindow::eventFilter(QObject* object, QEvent* event) {
    const bool isSessionTerminal = object == m_sshWidgets.outputBox || object == m_telnetWidgets.outputBox;
    if (!isSessionTerminal) {
        return QMainWindow::eventFilter(object, event);
    }
    auto* box = qobject_cast<QTextEdit*>(object);
    if (box == nullptr) {
        return QMainWindow::eventFilter(object, event);
    }
    if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseButtonDblClick) {
        removeSessionDraft(box);
        renderSessionDraft(box);
        return QMainWindow::eventFilter(object, event);
    }
    if (event->type() != QEvent::KeyPress) {
        return QMainWindow::eventFilter(object, event);
    }
    auto* keyEvent = static_cast<QKeyEvent*>(event);
    QString* draft = sessionDraftForBox(box);
    int* draftCursor = sessionDraftCursorForBox(box);
    if (draft == nullptr || draftCursor == nullptr) {
        return true;
    }

    if (keyEvent->matches(QKeySequence::Paste)) {
        const QString text = QApplication::clipboard()->text();
        if (!text.isEmpty()) {
            removeSessionDraft(box);
            draft->insert(*draftCursor, text);
            *draftCursor += text.size();
            renderSessionDraft(box);
        }
        return true;
    }
    if (keyEvent->matches(QKeySequence::Copy) && box->textCursor().hasSelection()) {
        return QMainWindow::eventFilter(object, event);
    }
    if (keyEvent->matches(QKeySequence::SelectAll)) {
        return QMainWindow::eventFilter(object, event);
    }

    const Qt::KeyboardModifiers modifiers = keyEvent->modifiers();
    removeSessionDraft(box);
    switch (keyEvent->key()) {
    case Qt::Key_Return:
    case Qt::Key_Enter:
        if (modifiers & Qt::ShiftModifier) {
            draft->insert(*draftCursor, QLatin1Char('\n'));
            ++(*draftCursor);
            renderSessionDraft(box);
            return true;
        }
        if (!draft->isEmpty()) {
            sendSessionTerminalBytes(box, draft->toUtf8());
        }
        sendSessionTerminalBytes(box, object == m_telnetWidgets.outputBox ? QByteArrayLiteral("\r\n") : QByteArrayLiteral("\n"));
        draft->clear();
        *draftCursor = 0;
        return true;
    case Qt::Key_Backspace:
        if (*draftCursor > 0) {
            draft->remove(*draftCursor - 1, 1);
            --(*draftCursor);
        } else if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArray(1, '\x7f'));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Delete:
        if (*draftCursor < draft->size()) {
            draft->remove(*draftCursor, 1);
        } else if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[3~"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Left:
        if (*draftCursor > 0) {
            --(*draftCursor);
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Right:
        if (*draftCursor < draft->size()) {
            ++(*draftCursor);
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Up:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[A"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Down:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArrayLiteral("\x1b[B"));
        }
        renderSessionDraft(box);
        return true;
    case Qt::Key_Home:
        *draftCursor = 0;
        renderSessionDraft(box);
        return true;
    case Qt::Key_End:
        *draftCursor = draft->size();
        renderSessionDraft(box);
        return true;
    case Qt::Key_PageUp:
    case Qt::Key_PageDown:
        renderSessionDraft(box);
        return QMainWindow::eventFilter(object, event);
    case Qt::Key_Tab:
        draft->insert(*draftCursor, QLatin1Char('\t'));
        ++(*draftCursor);
        renderSessionDraft(box);
        return true;
    case Qt::Key_Escape:
        if (draft->isEmpty()) {
            sendSessionTerminalBytes(box, QByteArray(1, '\x1b'));
        }
        renderSessionDraft(box);
        return true;
    default:
        break;
    }

    if (modifiers == Qt::ControlModifier && keyEvent->key() == Qt::Key_C) {
        if (box->textCursor().hasSelection()) {
            renderSessionDraft(box);
            return QMainWindow::eventFilter(object, event);
        }
        draft->clear();
        *draftCursor = 0;
        sendSessionTerminalBytes(box, QByteArray(1, '\x03'));
        return true;
    }
    if (modifiers == Qt::ControlModifier && keyEvent->key() >= Qt::Key_A && keyEvent->key() <= Qt::Key_Z) {
        const char controlByte = static_cast<char>(keyEvent->key() - Qt::Key_A + 1);
        sendSessionTerminalBytes(box, QByteArray(1, controlByte));
        renderSessionDraft(box);
        return true;
    }

    const QString text = keyEvent->text();
    if (!text.isEmpty() && !(modifiers & Qt::MetaModifier)) {
        draft->insert(*draftCursor, text);
        *draftCursor += text.size();
        renderSessionDraft(box);
        return true;
    }
    renderSessionDraft(box);
    return QMainWindow::eventFilter(object, event);
}

void MainWindow::applyDarkPalette() {
    qApp->setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    QPalette palette;
    if (m_settings->theme() == QStringLiteral("light")) {
        palette.setColor(QPalette::Window, QColor("#e5e9ed"));
        palette.setColor(QPalette::WindowText, QColor("#1f2730"));
        palette.setColor(QPalette::Base, QColor("#f5f7f8"));
        palette.setColor(QPalette::AlternateBase, QColor("#edf1f4"));
        palette.setColor(QPalette::Button, QColor("#d8dee5"));
        palette.setColor(QPalette::ButtonText, QColor("#1f2730"));
        palette.setColor(QPalette::Text, QColor("#1f2730"));
        palette.setColor(QPalette::Highlight, QColor("#cad6e2"));
        palette.setColor(QPalette::HighlightedText, QColor("#111111"));
        palette.setColor(QPalette::Light, QColor("#f1f4f7"));
        palette.setColor(QPalette::Midlight, QColor("#d5dce3"));
        palette.setColor(QPalette::Mid, QColor("#c4ced7"));
        palette.setColor(QPalette::Dark, QColor("#9ea9b5"));
        palette.setColor(QPalette::Shadow, QColor("#8994a0"));
    } else {
        palette.setColor(QPalette::Window, QColor("#15191f"));
        palette.setColor(QPalette::WindowText, QColor("#e7ecf2"));
        palette.setColor(QPalette::Base, QColor("#0f1318"));
        palette.setColor(QPalette::AlternateBase, QColor("#171d24"));
        palette.setColor(QPalette::Button, QColor("#242b35"));
        palette.setColor(QPalette::ButtonText, QColor("#eef2f6"));
        palette.setColor(QPalette::Text, QColor("#eef2f6"));
        palette.setColor(QPalette::Highlight, QColor("#39444f"));
        palette.setColor(QPalette::HighlightedText, QColor("#ffffff"));
        palette.setColor(QPalette::Light, QColor("#3d4653"));
        palette.setColor(QPalette::Midlight, QColor("#2b323c"));
        palette.setColor(QPalette::Mid, QColor("#2b323c"));
        palette.setColor(QPalette::Dark, QColor("#0d1014"));
        palette.setColor(QPalette::Shadow, QColor("#090b0d"));
    }
    qApp->setPalette(palette);
}

void MainWindow::applyStyleSheet() {
    if (m_settings->theme() == QStringLiteral("light")) {
        setStyleSheet(QStringLiteral(R"(
        QMainWindow { background:#e5e9ed; }
        QMenuBar { background:#d5dce3; color:#1f2730; border-bottom:1px solid #b5bfc9; spacing:4px; font-size:11px; }
        QMenuBar::item { background:transparent; color:#1f2730; padding:3px 6px; margin:1px; }
        QMenuBar::item:selected { background:#c8d1da; }
        QMenu { background:#f1f4f7; color:#1f2730; border:1px solid #b5bfc9; font-size:11px; }
        QMenu::item:selected { background:#d6e0e8; }
        QFrame#toolbarPanel, QFrame#workPane, QFrame#sessionPane { background:#eef2f5; border:1px solid #c2cbd4; }
        QLabel { color:#24303a; font-size:11px; }
        QLabel#titleLabel { font-size:14pt; font-weight:700; color:#1d2730; }
        QLabel#sectionLabel { font-size:10pt; font-weight:700; color:#1d2730; }
        QLabel#statusHint { color:#596676; }
        QListWidget, QTableWidget, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox, QSpinBox, QTabWidget::pane {
            background:#f5f7f8; color:#1f2730; border:1px solid #bcc7d2; selection-background-color:#d3dfec; selection-color:#111111;
        }
        QTextEdit#httpResponsePanel {
            border-radius:8px;
            padding:6px;
        }
        QPushButton#httpSendButton {
            min-width:190px;
            max-width:190px;
            min-height:26px;
            max-height:26px;
            border-radius:0px;
            font-weight:600;
        }
        QLineEdit, QComboBox, QSpinBox { min-height:20px; max-height:20px; padding:1px 5px; font-size:11px; }
        QListWidget::item { padding:4px 6px; }
        QListWidget::item:selected { background:#d3dfec; }
        QHeaderView::section { background:#e0e6ec; color:#1f2730; border:0; border-right:1px solid #ccd4dd; border-bottom:1px solid #ccd4dd; padding:3px 5px; font-weight:400; font-size:11px; }
        QPushButton { background:#d8dee5; color:#1f2730; border:1px solid #a7b2be; padding:2px 8px; min-height:22px; max-height:22px; font-size:11px; font-weight:500; }
        QPushButton:hover { background:#cfd6de; }
        QPushButton:pressed { background:#c1cad4; padding-top:3px; padding-left:9px; }
        QPushButton:disabled { color:#7c8895; background:#e8edf2; border:1px solid #c2cbd4; }
        QGroupBox { font-weight:700; color:#1f2730; border:1px solid #c2cbd4; margin-top:10px; padding-top:10px; background:#eef2f5; }
        QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
        QStatusBar { background:#eef2f5; color:#24303a; border-top:1px solid #c2cbd4; }
        QLabel#statusCell { background:#e8edf2; color:#24303a; border:1px solid #c2cbd4; padding:3px 7px; font-size:11px; }
        QPushButton#scanStartButton { font-size:11px; min-width:132px; max-width:132px; min-height:20px; max-height:20px; padding:0px 8px; font-weight:600; background:#d8dee5; border:1px solid #a7b2be; }
        QCheckBox { color:#24303a; font-size:11px; spacing:4px; }
        QPushButton#miniIconButton, QPushButton#scanSortButton { min-width:20px; max-width:20px; min-height:20px; max-height:20px; padding:0px; font-size:11px; font-weight:700; }
        QToolButton#scanGearButton { background:transparent; border:none; padding:0px; min-width:20px; max-width:20px; min-height:20px; max-height:20px; }
        QToolButton#scanGearButton::menu-indicator { image:none; width:0px; }
        QToolButton#scanGearButton:hover { background:transparent; border:none; }
        QToolButton#scanGearButton:pressed { background:transparent; border:none; }
    )"));
        return;
    }
    setStyleSheet(QStringLiteral(R"(
        QMainWindow { background:#15191f; }
        QMenuBar {
            background:#101419;
            color:#eef2f6;
            border-bottom:1px solid #2a313b;
            spacing:4px;
            font-size:11px;
        }
        QMenuBar::item {
            background:transparent;
            color:#eef2f6;
            padding:3px 6px;
            margin:1px;
        }
        QMenuBar::item:selected { background:#252c34; }
        QMenu {
            background:#171d24;
            color:#eef2f6;
            border:1px solid #36414d;
            font-size:11px;
        }
        QMenu::item:selected { background:#252c34; }
        QFrame#toolbarPanel, QFrame#workPane, QFrame#sessionPane {
            background:#171c22;
            border:1px solid #313944;
        }
        QLabel { color:#e7ecf2; font-size:11px; }
        QLabel#titleLabel { font-size:14pt; font-weight:700; color:#eef2f6; }
        QLabel#sectionLabel { font-size:10pt; font-weight:700; color:#eef2f6; }
        QLabel#statusHint { color:#9ca8b5; }
        QListWidget, QTableWidget, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox, QSpinBox, QTabWidget::pane {
            background:#0f1318;
            color:#eef2f6;
            border:1px solid #394451;
            selection-background-color:#39444f;
            selection-color:#ffffff;
        }
        QTextEdit#httpResponsePanel {
            border-radius:8px;
            padding:6px;
        }
        QPushButton#httpSendButton {
            min-width:190px;
            max-width:190px;
            min-height:26px;
            max-height:26px;
            border-radius:0px;
            font-weight:600;
        }
        QLineEdit, QComboBox, QSpinBox {
            min-height:20px;
            max-height:20px;
            padding:1px 5px;
            font-size:11px;
        }
        QListWidget::item { padding:4px 6px; }
        QListWidget::item:selected { background:#39444f; }
        QHeaderView::section {
            background:#1a2129;
            color:#eef2f6;
            border:0;
            border-right:1px solid #2c3642;
            border-bottom:1px solid #2c3642;
            padding:3px 5px;
            font-weight:400;
            font-size:11px;
        }
        QPushButton {
            background:#242c36;
            color:#eef2f6;
            border:1px solid #455262;
            padding:2px 8px;
            min-height:22px;
            max-height:22px;
            font-size:11px;
            font-weight:500;
        }
        QPushButton:hover { background:#2c3743; }
        QPushButton:pressed {
            background:#1d242d;
            padding-top:3px;
            padding-left:9px;
        }
        QPushButton:disabled {
            color:#798290;
            background:#1c222a;
            border:1px solid #2f3741;
        }
        QGroupBox {
            font-weight:700;
            color:#eef2f6;
            border:1px solid #313944;
            margin-top:10px;
            padding-top:10px;
            background:#171c22;
        }
        QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
        QStatusBar { background:#171c22; color:#e7ecf2; border-top:1px solid #313944; }
        QLabel#statusCell {
            background:#11161b;
            color:#eef2f6;
            border:1px solid #313944;
            padding:3px 7px;
            font-size:11px;
        }
        QPushButton#scanStartButton {
            font-size:11px;
            min-width:132px;
            max-width:132px;
            min-height:20px;
            max-height:20px;
            padding:0px 8px;
            font-weight:600;
            background:#242c36;
            border:1px solid #455262;
        }
        QCheckBox {
            color:#e7ecf2;
            font-size:11px;
            spacing:4px;
        }
        QPushButton#miniIconButton, QPushButton#scanSortButton {
            min-width:20px;
            max-width:20px;
            min-height:20px;
            max-height:20px;
            padding:0px;
            font-size:11px;
            font-weight:700;
        }
        QToolButton#scanGearButton {
            background:transparent;
            border:none;
            padding:0px;
            min-width:20px;
            max-width:20px;
            min-height:20px;
            max-height:20px;
        }
        QToolButton#scanGearButton::menu-indicator { image:none; width:0px; }
        QToolButton#scanGearButton:hover { background:transparent; border:none; }
        QToolButton#scanGearButton:pressed { background:transparent; border:none; }
    )"));
}

bool MainWindow::isLightTheme() const {
    return m_settings->theme() == QStringLiteral("light");
}

QColor MainWindow::terminalTextColor() const {
    return terminalPresetColor(m_settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint")));
}

QTextCharFormat MainWindow::sessionBaseTerminalFormat() const {
    return defaultTerminalFormat(terminalTextColor());
}

void MainWindow::animateScanButtonPulse() {
    if (m_scanStartButton == nullptr || m_scanner->isRunning()) {
        return;
    }
    const QColor baseBackground = isLightTheme() ? QColor("#d8dee5") : QColor("#242c36");
    const QColor baseBorder = isLightTheme() ? QColor("#a7b2be") : QColor("#455262");
    const QColor pulseBackground = isLightTheme() ? QColor("#c7efd5") : QColor("#3f6454");
    const QColor pulseBorder = isLightTheme() ? QColor("#59a277") : QColor("#86d0a3");
    auto* animation = new QVariantAnimation(m_scanStartButton);
    animation->setDuration(420);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    connect(animation, &QVariantAnimation::valueChanged, this, [this, baseBackground, baseBorder, pulseBackground, pulseBorder](const QVariant& value) {
        const qreal raw = value.toReal();
        const qreal blend = raw <= 0.5 ? raw * 2.0 : (1.0 - raw) * 2.0;
        const QColor background = blendColor(baseBackground, pulseBackground, blend);
        const QColor border = blendColor(baseBorder, pulseBorder, blend);
        m_scanStartButton->setStyleSheet(QStringLiteral(
            "QPushButton#scanStartButton {"
            " font-size:11px; min-width:132px; max-width:132px; min-height:20px; max-height:20px;"
            " padding:0px 8px; font-weight:700; color:%3; background:%1; border:1px solid %2; }")
            .arg(background.name(), border.name(), isLightTheme() ? QStringLiteral("#183025") : QStringLiteral("#ecfff3")));
    });
    connect(animation, &QVariantAnimation::finished, m_scanStartButton, [this]() {
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setStyleSheet(QString());
        }
    });
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

void MainWindow::refreshTerminalFormats() {
    m_sshTerminalBaseFormat = sessionBaseTerminalFormat();
    m_telnetTerminalBaseFormat = sessionBaseTerminalFormat();
    m_sshTerminalFormat = m_sshTerminalBaseFormat;
    m_telnetTerminalFormat = m_telnetTerminalBaseFormat;
}

void MainWindow::refreshScanTableColors() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");

    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        const auto* ipItem = m_scanTable->item(row, ScanColumnIp);
        const auto* gatewayItem = m_scanTable->item(row, ScanColumnGateway);
        const bool isGatewayHost = ipItem != nullptr
            && gatewayItem != nullptr
            && !gatewayItem->text().trimmed().isEmpty()
            && gatewayItem->text() != localizedMissingText(m_settings)
            && ipItem->text() == gatewayItem->text();
        for (int col = 0; col < m_scanTable->columnCount(); ++col) {
            auto* item = m_scanTable->item(row, col);
            if (item == nullptr) {
                continue;
            }
            item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
            item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
            QFont font = item->font();
            font.setBold(isGatewayHost);
            item->setFont(font);
        }
    }
    m_scanTable->viewport()->update();
}

QWidget* MainWindow::createHeader() {
    const QString language = m_settings->language();
    auto* frame = new QFrame(this);
    frame->setObjectName(QStringLiteral("appHeader"));
    auto* layout = new QHBoxLayout(frame);
    layout->setContentsMargins(10, 8, 10, 8);
    layout->setSpacing(8);

    auto* title = new QLabel(localizedWindowTitle(m_settings), frame);
    title->setObjectName(QStringLiteral("titleLabel"));
    layout->addWidget(title);
    layout->addStretch(1);

    auto* settingsButton = new QPushButton(uiText(language, "Настройки", "Settings"), frame);
    settingsButton->setMinimumWidth(96);
    connect(settingsButton, &QPushButton::clicked, this, &MainWindow::openSettingsDialog);
    layout->addWidget(settingsButton);
    return frame;
}

QWidget* MainWindow::createSidebar() {
    const QString language = m_settings->language();
    auto* frame = new QFrame(this);
    frame->setObjectName(QStringLiteral("navPanel"));
    frame->setMinimumWidth(180);
    frame->setMaximumWidth(230);

    auto* layout = new QVBoxLayout(frame);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    auto* title = new QLabel(uiText(language, "Разделы", "Sections"), frame);
    title->setObjectName(QStringLiteral("sectionLabel"));
    layout->addWidget(title);

    m_navList = new QListWidget(frame);
    m_navList->addItems({
        uiText(language, "Сканер IP", "IP Scanner"),
        QStringLiteral("HTTP / REQ"),
        QStringLiteral("Serial"),
        QStringLiteral("TCP"),
        QStringLiteral("UDP"),
        QStringLiteral("SSH"),
        QStringLiteral("Telnet"),
        QStringLiteral("SNMP Browser"),
    });
    connect(m_navList, &QListWidget::currentRowChanged, this, &MainWindow::syncCurrentPage);
    layout->addWidget(m_navList, 1);
    return frame;
}

QWidget* MainWindow::createScanPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(3, 3, 3, 3);
    root->setSpacing(3);

    auto* toolbar = new QFrame(page);
    toolbar->setObjectName(QStringLiteral("toolbarPanel"));
    auto* toolbarLayout = new QVBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(5, 5, 5, 5);
    toolbarLayout->setSpacing(4);

    auto* rangeRow = new QHBoxLayout();
    rangeRow->setSpacing(5);
    rangeRow->addWidget(new QLabel(uiText(language, "Диапазон IP:", "IP range:"), toolbar));
    m_scanStartIp = new QLineEdit(toolbar);
    m_scanStartIp->setFixedWidth(132);
    rangeRow->addWidget(m_scanStartIp);
    rangeRow->addWidget(new QLabel(uiText(language, "до", "to"), toolbar));
    m_scanEndIp = new QLineEdit(toolbar);
    m_scanEndIp->setFixedWidth(132);
    rangeRow->addWidget(m_scanEndIp);
    rangeRow->addWidget(new QLabel(uiText(language, "Адаптер:", "Adapter:"), toolbar));
    m_scanAdapterCombo = new QComboBox(toolbar);
    m_scanAdapterCombo->setFixedWidth(180);
    rangeRow->addWidget(m_scanAdapterCombo);
    rangeRow->addStretch(1);
    toolbarLayout->addLayout(rangeRow);

    auto* optionsRow = new QHBoxLayout();
    optionsRow->setSpacing(5);
    optionsRow->addWidget(new QLabel(uiText(language, "Авто IP:", "Auto IP:"), toolbar));
    m_scanAutoIpCheck = new QCheckBox(uiText(language, "вкл", "on"), toolbar);
    m_scanAutoIpCheck->setChecked(true);
    optionsRow->addWidget(m_scanAutoIpCheck);
    m_scanAutoScanCheck = new QCheckBox(uiText(language, "авто скан", "auto scan"), toolbar);
    m_scanAutoScanCheck->setChecked(m_settings->value(QStringLiteral("auto_scan_enabled"), false).toBool(false));
    optionsRow->addWidget(m_scanAutoScanCheck);
    optionsRow->addSpacing(12);
    optionsRow->addWidget(new QLabel(uiText(language, "Маска:", "Mask:"), toolbar));
    m_scanPrefixCombo = new QComboBox(toolbar);
    m_scanPrefixCombo->addItems({QStringLiteral("/24"), QStringLiteral("/23"), QStringLiteral("/22"), QStringLiteral("/16"), QStringLiteral("/32")});
    m_scanPrefixCombo->setCurrentText(QStringLiteral("/24"));
    m_scanPrefixCombo->setFixedWidth(70);
    optionsRow->addWidget(m_scanPrefixCombo);
    m_scanStartButton = new QPushButton(uiText(language, "▶ Старт", "▶ Start"), toolbar);
    m_scanStartButton->setObjectName(QStringLiteral("scanStartButton"));
    m_scanStartButton->setFixedWidth(132);
    optionsRow->addWidget(m_scanStartButton);
    m_scanToolsMenu = new QMenu(toolbar);
    for (int column = 0; column < ScanColumnCount; ++column) {
        auto* action = m_scanToolsMenu->addAction(scanColumnTitle(m_settings, column));
        action->setCheckable(true);
        action->setChecked(scanColumnVisibleByDefault(column));
        if (column == ScanColumnIp) {
            action->setEnabled(false);
        }
        connect(action, &QAction::toggled, this, [this](bool) {
            saveScanColumnVisibility();
            applyScanColumnVisibility();
        });
        m_scanColumnActions.insert(column, action);
    }
    m_scanToolsMenu->setTitle(uiText(language, "Колонки", "Columns"));

    m_scanSortButton = new QPushButton(toolbar);
    m_scanSortButton->setObjectName(QStringLiteral("scanSortButton"));
    m_scanSortButton->setToolTip(uiText(language, "Сортировка IP", "IP sort"));
    optionsRow->addWidget(m_scanSortButton);

    m_scanToolsButton = new QToolButton(toolbar);
    m_scanToolsButton->setObjectName(QStringLiteral("scanGearButton"));
    m_scanToolsButton->setAutoRaise(true);
    m_scanToolsButton->setPopupMode(QToolButton::InstantPopup);
    m_scanToolsButton->setMenu(m_scanToolsMenu);
    m_scanToolsButton->setToolTip(uiText(language, "Колонки таблицы", "Table columns"));
    optionsRow->addWidget(m_scanToolsButton);

    optionsRow->addStretch(1);
    toolbarLayout->addLayout(optionsRow);

    m_scanOnlineLabel = new QLabel(uiText(language, "Онлайн: 0", "Online: 0"), toolbar);
    m_scanOnlineLabel->hide();
    m_scanStopButton = new QPushButton(page);
    m_scanStopButton->hide();

    connect(m_scanStartButton, &QPushButton::clicked, this, [this]() {
        if (m_scanner->isRunning() || m_scanLaunchPending) {
            stopScan();
        } else {
            startScan();
        }
    });
    connect(m_scanStopButton, &QPushButton::clicked, this, &MainWindow::stopScan);
    connect(m_scanSortButton, &QPushButton::clicked, this, &MainWindow::toggleScanSortOrder);
    connect(m_scanStartIp, &QLineEdit::returnPressed, this, &MainWindow::startScan);
    connect(m_scanEndIp, &QLineEdit::returnPressed, this, &MainWindow::startScan);
    connect(m_scanAdapterCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        if (m_scanAutoIpCheck == nullptr || m_scanAutoIpCheck->isChecked()) {
            applyRangeFromCurrentAdapter();
        }
    });
    connect(m_scanPrefixCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        if (m_scanAutoIpCheck == nullptr || m_scanAutoIpCheck->isChecked()) {
            applyRangeFromCurrentAdapter();
        }
    });
    connect(m_scanAutoIpCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyRangeFromCurrentAdapter();
            updateScanFooter(uiText(m_settings, "Авто IP включен", "Auto IP enabled"));
        } else {
            updateScanFooter(uiText(m_settings, "Авто IP выключен", "Auto IP disabled"));
        }
    });
    connect(m_scanAutoScanCheck, &QCheckBox::toggled, this, [this](bool checked) {
        m_settings->setValue(QStringLiteral("auto_scan_enabled"), checked);
        m_settings->save();
        if (checked) {
            m_scanAutoScanTimer->start();
            updateScanFooter(uiText(m_settings, "Авто скан включен", "Auto scan enabled"));
            if (!m_scanner->isRunning()) {
                startScan();
            }
        } else {
            m_scanAutoScanTimer->stop();
            updateScanFooter(uiText(m_settings, "Авто скан выключен", "Auto scan disabled"));
        }
    });

    root->addWidget(toolbar, 0);

    auto* tableFrame = new QFrame(page);
    tableFrame->setObjectName(QStringLiteral("workPane"));
    auto* tableLayout = new QVBoxLayout(tableFrame);
    tableLayout->setContentsMargins(0, 0, 0, 0);

    m_scanTable = new QTableWidget(0, ScanColumnCount, tableFrame);
    QStringList headerLabels;
    for (int column = 0; column < ScanColumnCount; ++column) {
        headerLabels.append(scanColumnTitle(m_settings, column));
    }
    m_scanTable->setHorizontalHeaderLabels(headerLabels);
    m_scanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_scanTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_scanTable->setAlternatingRowColors(false);
    m_scanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanTable->setTextElideMode(Qt::ElideRight);
    m_scanTable->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_scanTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scanTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scanTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_scanTable->verticalHeader()->setVisible(false);
    m_scanTable->verticalHeader()->setDefaultSectionSize(23);
    m_scanTable->horizontalHeader()->setFixedHeight(23);
    m_scanTable->horizontalHeader()->setStretchLastSection(false);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnVendor, QHeaderView::Stretch);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnHostName, QHeaderView::Stretch);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnGateway, QHeaderView::Fixed);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnPort, QHeaderView::Fixed);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnType, QHeaderView::Fixed);
    m_scanTable->horizontalHeader()->setSectionResizeMode(ScanColumnWeb, QHeaderView::Fixed);
    m_scanTable->setShowGrid(true);
    m_scanTable->setColumnWidth(ScanColumnIp, 162);
    m_scanTable->setColumnWidth(ScanColumnPing, 70);
    m_scanTable->setColumnWidth(ScanColumnMac, 126);
    m_scanTable->setColumnWidth(ScanColumnWeb, 166);
    m_scanTable->setColumnWidth(ScanColumnGateway, 128);
    m_scanTable->setColumnWidth(ScanColumnPort, 108);
    m_scanTable->setColumnWidth(ScanColumnType, 78);
    connect(m_scanTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::updateSelectedHostPanel);
    connect(m_scanTable, &QTableWidget::customContextMenuRequested, this, &MainWindow::openScanContextMenu);
    tableLayout->addWidget(m_scanTable, 1);
    root->addWidget(tableFrame, 1);

    auto* footer = new QFrame(page);
    footer->setObjectName(QStringLiteral("toolbarPanel"));
    auto* footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(0, 0, 0, 0);
    footerLayout->setSpacing(1);
    m_scanFooterStateLabel = new QLabel(localizedScanIdleText(m_settings), footer);
    m_scanFooterThreadsLabel = new QLabel(localizedFoundDevicesText(m_settings, 0), footer);
    m_scanFooterStateLabel->setObjectName(QStringLiteral("statusCell"));
    m_scanFooterThreadsLabel->setObjectName(QStringLiteral("statusCell"));
    m_scanFooterStateLabel->setMinimumWidth(320);
    m_scanFooterThreadsLabel->setMinimumWidth(120);
    footerLayout->addWidget(m_scanFooterStateLabel, 1);
    footerLayout->addWidget(m_scanFooterThreadsLabel);
    root->addWidget(footer, 0);

    reloadAdapters();
    applySuggestedRange();
    applyScanColumnVisibility();
    updateScanSortButton();
    refreshScanToolbarIcons();
    if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()) {
        m_scanAutoScanTimer->start();
    }
    return page;
}

QWidget* MainWindow::createRequestPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QHBoxLayout(page);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(8);

    m_requestResponseEdit = new QTextEdit(page);
    m_requestResponseEdit->setReadOnly(true);
    m_requestResponseEdit->setFont(fixedFont());
    m_requestResponseEdit->setObjectName(QStringLiteral("httpResponsePanel"));
    m_requestResponseEdit->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_requestResponseEdit, 3);

    auto* controls = new QGroupBox(uiText(language, "Запрос", "Request"), page);
    auto* controlsLayout = new QVBoxLayout(controls);

    auto* form = new QGridLayout();
    m_requestMethodCombo = new QComboBox(controls);
    m_requestMethodCombo->addItems({QStringLiteral("GET"), QStringLiteral("POST"), QStringLiteral("PUT"), QStringLiteral("PATCH"), QStringLiteral("DELETE")});
    m_requestUrlEdit = new QLineEdit(controls);
    m_requestUserEdit = new QLineEdit(controls);
    m_requestPassEdit = new QLineEdit(controls);
    m_requestPassEdit->setEchoMode(QLineEdit::Password);
    m_requestTimeoutSpin = new QSpinBox(controls);
    m_requestTimeoutSpin->setRange(1, 120);
    m_requestTimeoutSpin->setValue(10);

    form->addWidget(new QLabel(uiText(language, "Метод", "Method"), controls), 0, 0);
    form->addWidget(m_requestMethodCombo, 0, 1);
    form->addWidget(new QLabel(QStringLiteral("URL"), controls), 1, 0);
    form->addWidget(m_requestUrlEdit, 1, 1);
    form->addWidget(new QLabel(uiText(language, "Логин", "Login"), controls), 2, 0);
    form->addWidget(m_requestUserEdit, 2, 1);
    form->addWidget(new QLabel(uiText(language, "Пароль", "Password"), controls), 3, 0);
    form->addWidget(m_requestPassEdit, 3, 1);
    form->addWidget(new QLabel(uiText(language, "Таймаут", "Timeout"), controls), 4, 0);
    form->addWidget(m_requestTimeoutSpin, 4, 1);
    controlsLayout->addLayout(form);

    auto* tabs = new QTabWidget(controls);
    auto* headersEditor = new CodeEditor(tabs);
    auto* paramsEditor = new CodeEditor(tabs);
    auto* bodyEditor = new CodeEditor(tabs);
    headersEditor->setPlainText(QStringLiteral("{\n    \"Accept\": \"application/json\"\n}"));
    paramsEditor->setPlainText(QStringLiteral("{}"));
    bodyEditor->setPlainText(QStringLiteral("{}"));
    m_requestHeadersEdit = headersEditor;
    m_requestParamsEdit = paramsEditor;
    m_requestBodyEdit = bodyEditor;
    tabs->addTab(m_requestHeadersEdit, uiText(language, "Заголовки", "Headers"));
    tabs->addTab(m_requestParamsEdit, uiText(language, "Параметры", "Params"));
    tabs->addTab(m_requestBodyEdit, uiText(language, "Тело", "Body"));
    auto* historyPlaceholder = new QWidget(tabs);
    tabs->addTab(historyPlaceholder, QStringLiteral("History"));
    tabs->setProperty("lastRealRequestTab", 0);
    controlsLayout->addWidget(tabs, 1);

    auto* actions = new QHBoxLayout();
    auto* sendButton = new QPushButton(uiText(language, "Отправить запрос", "Send Req"), controls);
    sendButton->setObjectName(QStringLiteral("httpSendButton"));
    actions->addStretch(1);
    actions->addWidget(sendButton);
    actions->addStretch(1);
    controlsLayout->addLayout(actions);

    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendHttpRequest);
    connect(tabs, &QTabWidget::currentChanged, this, [this, tabs, historyPlaceholder](int index) {
        const int historyIndex = tabs->indexOf(historyPlaceholder);
        if (index == historyIndex) {
            const int fallbackIndex = qBound(0, tabs->property("lastRealRequestTab").toInt(), qMax(0, historyIndex - 1));
            {
                QSignalBlocker blocker(tabs);
                tabs->setCurrentIndex(fallbackIndex);
            }
            openHttpHistory();
            return;
        }
        tabs->setProperty("lastRealRequestTab", index);
    });
    root->addWidget(controls, 2);
    return page;
}

QWidget* MainWindow::createSerialPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_serialWidgets.portCombo = new QComboBox(top);
    m_serialWidgets.baudCombo = new QComboBox(top);
    m_serialWidgets.baudCombo->addItems({QStringLiteral("1200"), QStringLiteral("2400"), QStringLiteral("4800"), QStringLiteral("9600"), QStringLiteral("19200"), QStringLiteral("38400"), QStringLiteral("57600"), QStringLiteral("115200")});
    m_serialWidgets.baudCombo->setCurrentText(QStringLiteral("9600"));
    m_serialWidgets.bitsCombo = new QComboBox(top);
    m_serialWidgets.bitsCombo->addItems({QStringLiteral("8"), QStringLiteral("7")});
    m_serialWidgets.parityCombo = new QComboBox(top);
    m_serialWidgets.parityCombo->addItem(uiText(language, "Нет", "None"), QStringLiteral("none"));
    m_serialWidgets.parityCombo->addItem(uiText(language, "Чет", "Even"), QStringLiteral("even"));
    m_serialWidgets.parityCombo->addItem(uiText(language, "Нечет", "Odd"), QStringLiteral("odd"));
    m_serialWidgets.stopBitsCombo = new QComboBox(top);
    m_serialWidgets.stopBitsCombo->addItems({QStringLiteral("1"), QStringLiteral("1.5"), QStringLiteral("2")});
    m_serialWidgets.flowControlCombo = new QComboBox(top);
    m_serialWidgets.flowControlCombo->addItem(uiText(language, "Нет", "None"), QStringLiteral("none"));
    m_serialWidgets.flowControlCombo->addItem(QStringLiteral("RTS/CTS"), QStringLiteral("hardware"));
    m_serialWidgets.flowControlCombo->addItem(QStringLiteral("XON/XOFF"), QStringLiteral("software"));
    m_serialWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_serialWidgets.eolCombo = new QComboBox(top);
    m_serialWidgets.eolCombo->addItem(uiText(language, "Нет", "None"), QStringLiteral("none"));
    m_serialWidgets.eolCombo->addItem(QStringLiteral("CR"), QStringLiteral("cr"));
    m_serialWidgets.eolCombo->addItem(QStringLiteral("LF"), QStringLiteral("lf"));
    m_serialWidgets.eolCombo->addItem(QStringLiteral("CRLF"), QStringLiteral("crlf"));
    m_serialWidgets.connectButton = new QPushButton(uiText(language, "Подключить", "Connect"), top);
    auto* refreshButton = new QPushButton(uiText(language, "Обновить", "Refresh"), top);

    topLayout->addWidget(new QLabel(uiText(language, "Порт", "Port"), top), 0, 0);
    topLayout->addWidget(m_serialWidgets.portCombo, 0, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Скорость", "Baud"), top), 0, 2);
    topLayout->addWidget(m_serialWidgets.baudCombo, 0, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Биты", "Bits"), top), 0, 4);
    topLayout->addWidget(m_serialWidgets.bitsCombo, 0, 5);
    topLayout->addWidget(new QLabel(uiText(language, "Четность", "Parity"), top), 0, 6);
    topLayout->addWidget(m_serialWidgets.parityCombo, 0, 7);
    topLayout->addWidget(new QLabel(uiText(language, "Стоп-биты", "Stop bits"), top), 1, 0);
    topLayout->addWidget(m_serialWidgets.stopBitsCombo, 1, 1);
    topLayout->addWidget(new QLabel(QStringLiteral("Flow"), top), 1, 2);
    topLayout->addWidget(m_serialWidgets.flowControlCombo, 1, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Окончание", "Line ending"), top), 1, 4);
    topLayout->addWidget(m_serialWidgets.eolCombo, 1, 5);
    topLayout->addWidget(m_serialWidgets.hexCheck, 1, 6);
    topLayout->addWidget(refreshButton, 1, 7);
    topLayout->addWidget(m_serialWidgets.connectButton, 1, 8);
    root->addWidget(top);

    m_serialWidgets.outputBox = new QTextEdit(page);
    m_serialWidgets.outputBox->setReadOnly(true);
    m_serialWidgets.outputBox->setFont(fixedFont());
    m_serialWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_serialWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_serialWidgets.inputEdit = new QLineEdit(sendBox);
    m_serialWidgets.inputEdit->setPlaceholderText(uiText(language, "Данные", "Payload"));
    auto* sendButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
    sendLayout->addWidget(new QLabel(uiText(language, "Ввод", "Input"), sendBox), 0, 0);
    sendLayout->addWidget(m_serialWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_serialWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("serial"), m_serialWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(refreshButton, &QPushButton::clicked, this, &MainWindow::refreshSerialPorts);
    connect(m_serialWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleSerial);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
    connect(m_serialWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });

    refreshSerialPorts();
    {
        const auto section = m_settings->section(QStringLiteral("serial"));
        m_serialWidgets.baudCombo->setCurrentText(section.value(QStringLiteral("baud")).toString(QStringLiteral("9600")));
        m_serialWidgets.bitsCombo->setCurrentText(section.value(QStringLiteral("data_bits")).toString(QStringLiteral("8")));
        setComboByData(m_serialWidgets.parityCombo, normalizedParityKey(section.value(QStringLiteral("parity")).toString(QStringLiteral("none"))));
        m_serialWidgets.stopBitsCombo->setCurrentText(section.value(QStringLiteral("stop_bits")).toString(QStringLiteral("1")));
        setComboByData(m_serialWidgets.flowControlCombo, normalizedFlowControlKey(section.value(QStringLiteral("flow_control")).toString(QStringLiteral("none"))));
        setComboByData(m_serialWidgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
    loadQuickCommands(QStringLiteral("serial"), m_serialWidgets);
    return page;
}

QWidget* MainWindow::createTcpPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_tcpWidgets.hostEdit = new QLineEdit(QStringLiteral("127.0.0.1"), top);
    m_tcpWidgets.hostEdit->setFixedWidth(250);
    m_tcpWidgets.portSpin = new QSpinBox(top);
    m_tcpWidgets.portSpin->setRange(1, 65535);
    m_tcpWidgets.portSpin->setValue(23);
    m_tcpWidgets.portSpin->setFixedWidth(88);
    m_tcpWidgets.localPortSpin = new QSpinBox(top);
    m_tcpWidgets.localPortSpin->setRange(0, 65535);
    m_tcpWidgets.localPortSpin->setValue(0);
    m_tcpWidgets.localPortSpin->setFixedWidth(88);
    m_tcpWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_tcpWidgets.eolCombo = new QComboBox(top);
    m_tcpWidgets.eolCombo->addItem(uiText(language, "Нет", "None"), QStringLiteral("none"));
    m_tcpWidgets.eolCombo->addItem(QStringLiteral("CR"), QStringLiteral("cr"));
    m_tcpWidgets.eolCombo->addItem(QStringLiteral("LF"), QStringLiteral("lf"));
    m_tcpWidgets.eolCombo->addItem(QStringLiteral("CRLF"), QStringLiteral("crlf"));
    m_tcpWidgets.noDelayCheck = new QCheckBox(QStringLiteral("NoDelay"), top);
    m_tcpWidgets.noDelayCheck->setChecked(true);
    m_tcpWidgets.keepAliveCheck = new QCheckBox(QStringLiteral("KeepAlive"), top);
    m_tcpWidgets.connectButton = new QPushButton(uiText(language, "Подключить", "Connect"), top);

    topLayout->addWidget(new QLabel(uiText(language, "Хост", "Host"), top), 0, 0);
    topLayout->addWidget(m_tcpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Удаленный порт", "Remote port"), top), 0, 2);
    topLayout->addWidget(m_tcpWidgets.portSpin, 0, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Локальный порт", "Local port"), top), 0, 4);
    topLayout->addWidget(m_tcpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_tcpWidgets.noDelayCheck, 1, 0);
    topLayout->addWidget(m_tcpWidgets.keepAliveCheck, 1, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Окончание", "Line ending"), top), 1, 2);
    topLayout->addWidget(m_tcpWidgets.eolCombo, 1, 3);
    topLayout->addWidget(m_tcpWidgets.hexCheck, 1, 4);
    topLayout->addWidget(m_tcpWidgets.connectButton, 1, 5);
    topLayout->setColumnStretch(1, 1);
    topLayout->setColumnStretch(5, 0);
    root->addWidget(top);

    m_tcpWidgets.outputBox = new QTextEdit(page);
    m_tcpWidgets.outputBox->setReadOnly(true);
    m_tcpWidgets.outputBox->setFont(fixedFont());
    m_tcpWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_tcpWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_tcpWidgets.inputEdit = new QLineEdit(sendBox);
    m_tcpWidgets.inputEdit->setPlaceholderText(uiText(language, "Данные", "Payload"));
    auto* sendButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
    sendLayout->addWidget(new QLabel(uiText(language, "Ввод", "Input"), sendBox), 0, 0);
    sendLayout->addWidget(m_tcpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_tcpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("tcp"), m_tcpWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(m_tcpWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleTcp);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendTcpPayload);
    connect(m_tcpWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendTcpPayload);
    connect(m_tcpWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
    connect(m_tcpWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("tcp"), m_tcpWidgets); });
    {
        const auto section = m_settings->section(QStringLiteral("tcp"));
        m_tcpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString(QStringLiteral("127.0.0.1")));
        m_tcpWidgets.portSpin->setValue(section.value(QStringLiteral("port")).toInt(23));
        m_tcpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_tcpWidgets.noDelayCheck->setChecked(section.value(QStringLiteral("no_delay")).toBool(true));
        m_tcpWidgets.keepAliveCheck->setChecked(section.value(QStringLiteral("keep_alive")).toBool(false));
        setComboByData(m_tcpWidgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
    loadQuickCommands(QStringLiteral("tcp"), m_tcpWidgets);
    return page;
}

QWidget* MainWindow::createUdpPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);
    root->setSpacing(6);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(8, 8, 8, 8);
    topLayout->setHorizontalSpacing(6);
    topLayout->setVerticalSpacing(6);

    m_udpWidgets.hostEdit = new QLineEdit(QStringLiteral("127.0.0.1"), top);
    m_udpWidgets.hostEdit->setFixedWidth(250);
    m_udpWidgets.remotePortSpin = new QSpinBox(top);
    m_udpWidgets.remotePortSpin->setRange(1, 65535);
    m_udpWidgets.remotePortSpin->setValue(52381);
    m_udpWidgets.remotePortSpin->setFixedWidth(88);
    m_udpWidgets.localPortSpin = new QSpinBox(top);
    m_udpWidgets.localPortSpin->setRange(0, 65535);
    m_udpWidgets.localPortSpin->setValue(0);
    m_udpWidgets.localPortSpin->setFixedWidth(88);
    m_udpWidgets.hexCheck = new QCheckBox(QStringLiteral("HEX"), top);
    m_udpWidgets.eolCombo = new QComboBox(top);
    m_udpWidgets.eolCombo->addItem(uiText(language, "Нет", "None"), QStringLiteral("none"));
    m_udpWidgets.eolCombo->addItem(QStringLiteral("CR"), QStringLiteral("cr"));
    m_udpWidgets.eolCombo->addItem(QStringLiteral("LF"), QStringLiteral("lf"));
    m_udpWidgets.eolCombo->addItem(QStringLiteral("CRLF"), QStringLiteral("crlf"));
    m_udpWidgets.reuseAddressCheck = new QCheckBox(QStringLiteral("Reuse"), top);
    m_udpWidgets.reuseAddressCheck->setChecked(true);
    m_udpWidgets.connectButton = new QPushButton(uiText(language, "Открыть", "Open"), top);

    topLayout->addWidget(new QLabel(uiText(language, "Удаленный хост", "Remote host"), top), 0, 0);
    topLayout->addWidget(m_udpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Удаленный порт", "Remote port"), top), 0, 2);
    topLayout->addWidget(m_udpWidgets.remotePortSpin, 0, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Локальный порт", "Local port"), top), 0, 4);
    topLayout->addWidget(m_udpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_udpWidgets.reuseAddressCheck, 1, 0);
    topLayout->addWidget(new QLabel(uiText(language, "Окончание", "Line ending"), top), 1, 1);
    topLayout->addWidget(m_udpWidgets.eolCombo, 1, 2);
    topLayout->addWidget(m_udpWidgets.hexCheck, 1, 3);
    topLayout->addWidget(m_udpWidgets.connectButton, 1, 5);
    topLayout->setColumnStretch(1, 1);
    topLayout->setColumnStretch(5, 0);
    root->addWidget(top);

    m_udpWidgets.outputBox = new QTextEdit(page);
    m_udpWidgets.outputBox->setReadOnly(true);
    m_udpWidgets.outputBox->setFont(fixedFont());
    m_udpWidgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    root->addWidget(m_udpWidgets.outputBox, 1);

    auto* sendBox = new QFrame(page);
    sendBox->setObjectName(QStringLiteral("workPane"));
    auto* sendLayout = new QGridLayout(sendBox);
    sendLayout->setContentsMargins(8, 8, 8, 8);
    sendLayout->setHorizontalSpacing(6);
    sendLayout->setVerticalSpacing(6);
    m_udpWidgets.inputEdit = new QLineEdit(sendBox);
    m_udpWidgets.inputEdit->setPlaceholderText(uiText(language, "Данные", "Payload"));
    auto* sendButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
    sendLayout->addWidget(new QLabel(uiText(language, "Ввод", "Input"), sendBox), 0, 0);
    sendLayout->addWidget(m_udpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 3; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(QStringLiteral("▶ %1").arg(i + 1), sendBox);
        m_udpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(QStringLiteral("Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("udp"), m_udpWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(m_udpWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleUdp);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendUdpPayload);
    connect(m_udpWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendUdpPayload);
    connect(m_udpWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
    connect(m_udpWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("udp"), m_udpWidgets); });
    {
        const auto section = m_settings->section(QStringLiteral("udp"));
        m_udpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString(QStringLiteral("127.0.0.1")));
        m_udpWidgets.remotePortSpin->setValue(section.value(QStringLiteral("remote_port")).toInt(52381));
        m_udpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_udpWidgets.reuseAddressCheck->setChecked(section.value(QStringLiteral("reuse_address")).toBool(true));
        setComboByData(m_udpWidgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
    loadQuickCommands(QStringLiteral("udp"), m_udpWidgets);
    return page;
}

QWidget* MainWindow::createSessionPage(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(6, 6, 6, 6);

    auto* splitter = new QSplitter(Qt::Horizontal, page);
    splitter->setHandleWidth(1);
    root->addWidget(splitter, 1);

    auto* left = new QFrame(splitter);
    left->setObjectName(QStringLiteral("sessionPane"));
    left->setMinimumWidth(240);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->setContentsMargins(8, 8, 8, 8);

    auto* profilesBox = new QGroupBox(kind + uiText(language, " профили", " profiles"), left);
    auto* profilesLayout = new QVBoxLayout(profilesBox);
    widgets.profiles = new QListWidget(profilesBox);
    profilesLayout->addWidget(widgets.profiles, 1);
    auto* profileButtons = new QHBoxLayout();
    auto* newButton = new QPushButton(uiText(language, "Новый", "New"), profilesBox);
    auto* deleteButton = new QPushButton(uiText(language, "Удалить", "Delete"), profilesBox);
    profileButtons->addWidget(newButton);
    profileButtons->addWidget(deleteButton);
    profilesLayout->addLayout(profileButtons);
    leftLayout->addWidget(profilesBox, 1);

    auto* right = new QFrame(splitter);
    right->setObjectName(QStringLiteral("sessionPane"));
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(8, 8, 8, 8);

    auto* workspaceBox = new QGroupBox(kind + uiText(language, " рабочая область", " workspace"), right);
    auto* grid = new QGridLayout(workspaceBox);
    grid->setHorizontalSpacing(6);
    grid->setVerticalSpacing(6);
    grid->setColumnStretch(1, 1);
    grid->setColumnStretch(3, 1);
    widgets.nameEdit = new QLineEdit(workspaceBox);
    widgets.hostEdit = new QLineEdit(workspaceBox);
    widgets.portSpin = new QSpinBox(workspaceBox);
    widgets.portSpin->setRange(1, 65535);
    widgets.portSpin->setValue(defaultPort);
    widgets.portSpin->setFixedWidth(92);
    widgets.userEdit = new QLineEdit(workspaceBox);
    widgets.passEdit = new QLineEdit(workspaceBox);
    widgets.passEdit->setEchoMode(QLineEdit::Password);
    widgets.connectButton = new QPushButton(uiText(language, "Подключить", "Connect"), workspaceBox);
    widgets.saveButton = new QPushButton(uiText(language, "Сохранить профиль", "Save profile"), workspaceBox);

    auto* portRow = new QWidget(workspaceBox);
    auto* portLayout = new QHBoxLayout(portRow);
    portLayout->setContentsMargins(0, 0, 0, 0);
    portLayout->setSpacing(6);
    portLayout->addWidget(new QLabel(uiText(language, "Порт", "Port"), portRow));
    portLayout->addWidget(widgets.portSpin);
    portLayout->addStretch(1);

    auto* actionsRow = new QWidget(workspaceBox);
    auto* actionsLayout = new QHBoxLayout(actionsRow);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(6);
    actionsLayout->addWidget(widgets.saveButton);
    actionsLayout->addWidget(widgets.connectButton);

    grid->addWidget(new QLabel(uiText(language, "Имя", "Name"), workspaceBox), 0, 0);
    grid->addWidget(widgets.nameEdit, 0, 1);
    grid->addWidget(new QLabel(uiText(language, "Хост", "Host"), workspaceBox), 0, 2);
    grid->addWidget(widgets.hostEdit, 0, 3);
    grid->addWidget(portRow, 0, 4, 1, 2);
    grid->addWidget(new QLabel(uiText(language, "Логин", "Login"), workspaceBox), 1, 0);
    grid->addWidget(widgets.userEdit, 1, 1);
    grid->addWidget(new QLabel(uiText(language, "Пароль", "Password"), workspaceBox), 1, 2);
    grid->addWidget(widgets.passEdit, 1, 3);
    grid->addWidget(actionsRow, 1, 4, 1, 2);
    rightLayout->addWidget(workspaceBox);

    widgets.statusLabel = new QLabel(uiText(language, "Не подключено", "Not connected"), right);
    widgets.statusLabel->setObjectName(QStringLiteral("statusHint"));
    rightLayout->addWidget(widgets.statusLabel);

    widgets.outputBox = new QTextEdit(right);
    widgets.outputBox->setReadOnly(true);
    widgets.outputBox->setFont(fixedFont());
    widgets.outputBox->setLineWrapMode(QTextEdit::NoWrap);
    widgets.outputBox->setFocusPolicy(Qt::StrongFocus);
    widgets.outputBox->setUndoRedoEnabled(false);
    widgets.outputBox->installEventFilter(this);
    rightLayout->addWidget(widgets.outputBox, 1);

    splitter->addWidget(left);
    splitter->addWidget(right);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({260, 980});

    connect(newButton, &QPushButton::clicked, this, [this, &widgets, defaultPort]() { newSessionProfile(widgets, defaultPort); });
    connect(deleteButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { deleteSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(widgets.saveButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { saveSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(widgets.profiles, &QListWidget::itemSelectionChanged, this, [this, &widgets, defaultPort]() {
        const auto* item = widgets.profiles->currentItem();
        if (item == nullptr) {
            return;
        }
        const auto profile = item->data(Qt::UserRole).value<nt::SessionProfile>();
        applySessionProfile(profile, widgets);
        Q_UNUSED(defaultPort)
    });

    loadSessionProfiles(kind.toLower(), widgets, defaultPort);
    return page;
}

QWidget* MainWindow::createSnmpPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(3, 3, 3, 3);
    root->setSpacing(2);

    auto* toolbar = new QFrame(page);
    toolbar->setObjectName(QStringLiteral("toolbarPanel"));
    auto* toolbarLayout = new QVBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(5, 4, 5, 4);
    toolbarLayout->setSpacing(2);

    m_snmpWidgets.hostEdit = new QLineEdit(toolbar);
    m_snmpWidgets.portSpin = new QSpinBox(toolbar);
    m_snmpWidgets.portSpin->setRange(1, 65535);
    m_snmpWidgets.portSpin->setValue(161);
    m_snmpWidgets.versionCombo = new QComboBox(toolbar);
    m_snmpWidgets.versionCombo->addItem(QStringLiteral("SNMP v1"), QStringLiteral("1"));
    m_snmpWidgets.versionCombo->addItem(QStringLiteral("SNMP v2c"), QStringLiteral("2c"));
    m_snmpWidgets.versionCombo->addItem(QStringLiteral("SNMP v3"), QStringLiteral("3"));
    m_snmpWidgets.loadButton = new QPushButton(uiText(language, "Опросить все OID", "Walk all OIDs"), toolbar);
    m_snmpWidgets.loadButton->setObjectName(QStringLiteral("scanStartButton"));

    m_snmpWidgets.communityEdit = new QLineEdit(toolbar);
    m_snmpWidgets.writeCommunityEdit = new QLineEdit(toolbar);
    m_snmpWidgets.v3UserEdit = new QLineEdit(toolbar);
    m_snmpWidgets.v3SecurityLevelCombo = new QComboBox(toolbar);
    m_snmpWidgets.v3SecurityLevelCombo->addItem(QStringLiteral("noAuthNoPriv"), QStringLiteral("noAuthNoPriv"));
    m_snmpWidgets.v3SecurityLevelCombo->addItem(QStringLiteral("authNoPriv"), QStringLiteral("authNoPriv"));
    m_snmpWidgets.v3SecurityLevelCombo->addItem(QStringLiteral("authPriv"), QStringLiteral("authPriv"));
    m_snmpWidgets.v3AuthProtocolCombo = new QComboBox(toolbar);
    m_snmpWidgets.v3AuthProtocolCombo->addItem(QStringLiteral("SHA"), QStringLiteral("SHA"));
    m_snmpWidgets.v3AuthProtocolCombo->addItem(QStringLiteral("MD5"), QStringLiteral("MD5"));
    m_snmpWidgets.v3AuthPasswordEdit = new QLineEdit(toolbar);
    m_snmpWidgets.v3AuthPasswordEdit->setEchoMode(QLineEdit::Password);
    m_snmpWidgets.v3PrivacyProtocolCombo = new QComboBox(toolbar);
    m_snmpWidgets.v3PrivacyProtocolCombo->addItem(QStringLiteral("AES"), QStringLiteral("AES"));
    m_snmpWidgets.v3PrivacyProtocolCombo->addItem(QStringLiteral("DES"), QStringLiteral("DES"));
    m_snmpWidgets.v3PrivacyPasswordEdit = new QLineEdit(toolbar);
    m_snmpWidgets.v3PrivacyPasswordEdit->setEchoMode(QLineEdit::Password);

    m_snmpWidgets.filterEdit = new QLineEdit(toolbar);
    m_snmpWidgets.filterEdit->setClearButtonEnabled(true);
    m_snmpWidgets.filterEdit->setPlaceholderText(uiText(language, "Фильтр: OID / параметр / значение", "Filter: OID / parameter / value"));

    const auto configureSnmpField = [](QWidget* widget, int width = 0) {
        if (widget == nullptr) {
            return;
        }
        widget->setFixedHeight(19);
        if (width > 0) {
            widget->setFixedWidth(width);
        }
    };

    m_snmpWidgets.hostEdit->setPlaceholderText(QStringLiteral("0.0.0.0"));
    m_snmpWidgets.communityEdit->setPlaceholderText(uiText(language, "public", "public"));
    m_snmpWidgets.writeCommunityEdit->setPlaceholderText(uiText(language, "private / optional", "private / optional"));
    m_snmpWidgets.v3UserEdit->setPlaceholderText(uiText(language, "snmpuser", "snmpuser"));
    m_snmpWidgets.v3AuthPasswordEdit->setPlaceholderText(uiText(language, "Auth password", "Auth password"));
    m_snmpWidgets.v3PrivacyPasswordEdit->setPlaceholderText(uiText(language, "Privacy password", "Privacy password"));

    configureSnmpField(m_snmpWidgets.hostEdit, 150);
    configureSnmpField(m_snmpWidgets.portSpin, 70);
    configureSnmpField(m_snmpWidgets.versionCombo, 104);
    configureSnmpField(m_snmpWidgets.communityEdit, 206);
    configureSnmpField(m_snmpWidgets.writeCommunityEdit, 206);
    configureSnmpField(m_snmpWidgets.v3UserEdit, 140);
    configureSnmpField(m_snmpWidgets.v3SecurityLevelCombo, 130);
    configureSnmpField(m_snmpWidgets.v3AuthProtocolCombo, 88);
    configureSnmpField(m_snmpWidgets.v3AuthPasswordEdit, 150);
    configureSnmpField(m_snmpWidgets.v3PrivacyProtocolCombo, 88);
    configureSnmpField(m_snmpWidgets.v3PrivacyPasswordEdit, 150);
    configureSnmpField(m_snmpWidgets.filterEdit, 255);
    m_snmpWidgets.loadButton->setFixedHeight(19);
    m_snmpWidgets.loadButton->setFixedWidth(118);

    auto* primaryRow = new QHBoxLayout();
    primaryRow->setContentsMargins(0, 0, 0, 0);
    primaryRow->setSpacing(5);
    primaryRow->addWidget(new QLabel(uiText(language, "IP / хост:", "IP / host:"), toolbar));
    primaryRow->addWidget(m_snmpWidgets.hostEdit);
    primaryRow->addWidget(new QLabel(uiText(language, "Порт:", "Port:"), toolbar));
    primaryRow->addWidget(m_snmpWidgets.portSpin);
    primaryRow->addWidget(new QLabel(uiText(language, "Версия:", "Version:"), toolbar));
    primaryRow->addWidget(m_snmpWidgets.versionCombo);
    primaryRow->addStretch(1);
    toolbarLayout->addLayout(primaryRow);

    m_snmpWidgets.securityStack = new QStackedWidget(toolbar);
    auto* communityPage = new QWidget(m_snmpWidgets.securityStack);
    auto* communityLayout = new QHBoxLayout(communityPage);
    communityLayout->setContentsMargins(0, 0, 0, 0);
    communityLayout->setSpacing(5);
    communityLayout->addWidget(new QLabel(uiText(language, "Чтение:", "Read:"), communityPage));
    communityLayout->addWidget(m_snmpWidgets.communityEdit);
    communityLayout->addWidget(new QLabel(uiText(language, "Запись:", "Write:"), communityPage));
    communityLayout->addWidget(m_snmpWidgets.writeCommunityEdit);
    m_snmpWidgets.securityStack->addWidget(communityPage);

    auto* v3Page = new QWidget(m_snmpWidgets.securityStack);
    auto* v3Layout = new QVBoxLayout(v3Page);
    v3Layout->setContentsMargins(0, 0, 0, 0);
    v3Layout->setSpacing(2);
    auto* v3Row1 = new QHBoxLayout();
    v3Row1->setContentsMargins(0, 0, 0, 0);
    v3Row1->setSpacing(5);
    v3Row1->addWidget(new QLabel(uiText(language, "Пользователь:", "User:"), v3Page));
    v3Row1->addWidget(m_snmpWidgets.v3UserEdit);
    v3Row1->addWidget(new QLabel(uiText(language, "Security:", "Security:"), v3Page));
    v3Row1->addWidget(m_snmpWidgets.v3SecurityLevelCombo);
    v3Row1->addWidget(new QLabel(uiText(language, "Auth:", "Auth:"), v3Page));
    v3Row1->addWidget(m_snmpWidgets.v3AuthProtocolCombo);
    v3Row1->addWidget(new QLabel(uiText(language, "Auth pass:", "Auth pass:"), v3Page));
    v3Row1->addWidget(m_snmpWidgets.v3AuthPasswordEdit);
    auto* v3Row2 = new QHBoxLayout();
    v3Row2->setContentsMargins(0, 0, 0, 0);
    v3Row2->setSpacing(5);
    v3Row2->addWidget(new QLabel(uiText(language, "Privacy:", "Privacy:"), v3Page));
    v3Row2->addWidget(m_snmpWidgets.v3PrivacyProtocolCombo);
    v3Row2->addWidget(new QLabel(uiText(language, "Privacy pass:", "Privacy pass:"), v3Page));
    v3Row2->addWidget(m_snmpWidgets.v3PrivacyPasswordEdit);
    v3Layout->addLayout(v3Row1);
    v3Layout->addLayout(v3Row2);
    m_snmpWidgets.securityStack->addWidget(v3Page);
    auto* securityRow = new QHBoxLayout();
    securityRow->setContentsMargins(0, 0, 0, 0);
    securityRow->setSpacing(5);
    securityRow->addWidget(m_snmpWidgets.securityStack, 0, Qt::AlignLeft);
    securityRow->addWidget(m_snmpWidgets.loadButton, 0, Qt::AlignTop);
    securityRow->addStretch(1);
    toolbarLayout->addLayout(securityRow);

    root->addWidget(toolbar, 0);

    auto* tableFrame = new QFrame(page);
    tableFrame->setObjectName(QStringLiteral("workPane"));
    auto* tableLayout = new QVBoxLayout(tableFrame);
    tableLayout->setContentsMargins(0, 0, 0, 0);

    m_snmpWidgets.table = new QTableWidget(0, 4, tableFrame);
    m_snmpWidgets.table->setHorizontalHeaderLabels({
        QStringLiteral("OID"),
        uiText(language, "Параметр", "Parameter"),
        uiText(language, "Тип", "Type"),
        uiText(language, "Значение", "Value"),
    });
    m_snmpWidgets.table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_snmpWidgets.table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_snmpWidgets.table->setAlternatingRowColors(false);
    m_snmpWidgets.table->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed | QAbstractItemView::SelectedClicked);
    m_snmpWidgets.table->setTextElideMode(Qt::ElideRight);
    m_snmpWidgets.table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_snmpWidgets.table->setShowGrid(true);
    m_snmpWidgets.table->verticalHeader()->setVisible(false);
    m_snmpWidgets.table->verticalHeader()->setDefaultSectionSize(22);
    m_snmpWidgets.table->horizontalHeader()->setFixedHeight(22);
    m_snmpWidgets.table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    m_snmpWidgets.table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_snmpWidgets.table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
    m_snmpWidgets.table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_snmpWidgets.table->setColumnWidth(0, 278);
    m_snmpWidgets.table->setColumnWidth(2, 86);
    tableLayout->addWidget(m_snmpWidgets.table, 1);
    root->addWidget(tableFrame, 1);

    auto* footer = new QFrame(page);
    footer->setObjectName(QStringLiteral("toolbarPanel"));
    auto* footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(0, 0, 0, 0);
    footerLayout->setSpacing(1);
    m_snmpWidgets.statusLabel = new QLabel(uiText(language, "OID еще не загружены", "OIDs are not loaded yet"), footer);
    m_snmpWidgets.statusLabel->setObjectName(QStringLiteral("statusCell"));
    footerLayout->addWidget(m_snmpWidgets.statusLabel, 1);
    footerLayout->addWidget(m_snmpWidgets.filterEdit);
    root->addWidget(footer, 0);

    const auto snmpSection = m_settings->section(QStringLiteral("snmp"));
    m_snmpWidgets.versionCombo->setCurrentIndex(qMax(0, m_snmpWidgets.versionCombo->findData(snmpSection.value(QStringLiteral("version")).toString(QStringLiteral("2c")))));
    m_snmpWidgets.hostEdit->setText(snmpSection.value(QStringLiteral("host")).toString());
    m_snmpWidgets.portSpin->setValue(snmpSection.value(QStringLiteral("port")).toInt(161));
    m_snmpWidgets.communityEdit->setText(snmpSection.value(QStringLiteral("read_community")).toString());
    m_snmpWidgets.writeCommunityEdit->setText(snmpSection.value(QStringLiteral("write_community")).toString());
    m_snmpWidgets.v3UserEdit->setText(snmpSection.value(QStringLiteral("v3_user")).toString());
    m_snmpWidgets.v3SecurityLevelCombo->setCurrentIndex(qMax(0, m_snmpWidgets.v3SecurityLevelCombo->findData(snmpSection.value(QStringLiteral("v3_security_level")).toString(QStringLiteral("noAuthNoPriv")))));
    m_snmpWidgets.v3AuthProtocolCombo->setCurrentIndex(qMax(0, m_snmpWidgets.v3AuthProtocolCombo->findData(snmpSection.value(QStringLiteral("v3_auth_protocol")).toString(QStringLiteral("SHA")))));
    m_snmpWidgets.v3AuthPasswordEdit->setText(snmpSection.value(QStringLiteral("v3_auth_password")).toString());
    m_snmpWidgets.v3PrivacyProtocolCombo->setCurrentIndex(qMax(0, m_snmpWidgets.v3PrivacyProtocolCombo->findData(snmpSection.value(QStringLiteral("v3_privacy_protocol")).toString(QStringLiteral("AES")))));
    m_snmpWidgets.v3PrivacyPasswordEdit->setText(snmpSection.value(QStringLiteral("v3_privacy_password")).toString());

    connect(m_snmpWidgets.loadButton, &QPushButton::clicked, this, &MainWindow::loadSnmpOidList);
    connect(m_snmpWidgets.table, &QTableWidget::itemChanged, this, &MainWindow::handleSnmpValueEdited);
    connect(m_snmpWidgets.filterEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        applySnmpTableFilter();
    });
    connect(m_snmpWidgets.hostEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.portSpin, &QSpinBox::valueChanged, this, [this](int) { persistSnmpSettingsFromUi(); });
    connect(m_snmpWidgets.communityEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.writeCommunityEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.v3UserEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.v3SecurityLevelCombo, &QComboBox::currentTextChanged, this, [this]() { persistSnmpSettingsFromUi(); refreshSnmpVersionUi(); });
    connect(m_snmpWidgets.v3AuthProtocolCombo, &QComboBox::currentTextChanged, this, [this]() { persistSnmpSettingsFromUi(); });
    connect(m_snmpWidgets.v3AuthPasswordEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.v3PrivacyProtocolCombo, &QComboBox::currentTextChanged, this, [this]() { persistSnmpSettingsFromUi(); });
    connect(m_snmpWidgets.v3PrivacyPasswordEdit, &QLineEdit::editingFinished, this, &MainWindow::persistSnmpSettingsFromUi);
    connect(m_snmpWidgets.versionCombo, &QComboBox::currentTextChanged, this, [this]() {
        refreshSnmpVersionUi();
        persistSnmpSettingsFromUi();
    });

    refreshSnmpVersionUi();
    return page;
}

QWidget* MainWindow::createPlaceholderPage(const QString& title, const QString& text) {
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(12, 12, 12, 12);

    auto* box = new QFrame(page);
    box->setObjectName(QStringLiteral("workPane"));
    auto* boxLayout = new QVBoxLayout(box);
    auto* titleLabel = new QLabel(title, box);
    titleLabel->setObjectName(QStringLiteral("sectionLabel"));
    auto* textLabel = new QLabel(text, box);
    textLabel->setWordWrap(true);
    textLabel->setObjectName(QStringLiteral("statusHint"));
    boxLayout->addWidget(titleLabel);
    boxLayout->addWidget(textLabel);
    boxLayout->addStretch(1);
    root->addWidget(box, 1);
    return page;
}

void MainWindow::configureMenuBar() {
    const QString language = m_settings->language();
    auto* mainMenu = menuBar();
    mainMenu->setNativeMenuBar(false);
    mainMenu->clear();

    auto* goToMenu = mainMenu->addMenu(uiText(language, "Функции", "Tools"));
    const QList<QPair<QString, int>> pages {
        {uiText(language, "Сканер IP", "IP Scanner"), 0},
        {QStringLiteral("HTTP / REQ"), 1},
        {QStringLiteral("Serial"), 2},
        {QStringLiteral("TCP"), 3},
        {QStringLiteral("UDP"), 4},
        {QStringLiteral("SSH"), 5},
        {QStringLiteral("Telnet"), 6},
        {QStringLiteral("SNMP Browser"), 7},
    };
    for (const auto& item : pages) {
        goToMenu->addAction(item.first, this, [this, index = item.second]() { syncCurrentPage(index); });
    }

    auto* commandsMenu = mainMenu->addMenu(uiText(language, "Обновление", "Refresh"));
    commandsMenu->addAction(uiText(language, "Автодиапазон", "Auto range"), this, &MainWindow::applySuggestedRange);
    commandsMenu->addAction(uiText(language, "Обновить диапазон", "Refresh range"), this, &MainWindow::resolveHostnameRange);
    commandsMenu->addAction(uiText(language, "Обновить адаптеры", "Refresh adapters"), this, &MainWindow::reloadAdapters);

    m_favoritesMenu = mainMenu->addMenu(uiText(language, "Анализ сети", "Network Analysis"));
    refreshFavoritesMenu();

    mainMenu->addAction(uiText(language, "Настройки", "Settings"), this, &MainWindow::openSettingsDialog);

    auto* helpMenu = mainMenu->addMenu(uiText(language, "Справка", "Help"));
    helpMenu->addAction(uiText(language, "Руководство", "Guide"), this, [this]() {
        QMessageBox::information(
            this,
            uiText(m_settings, "Руководство", "Guide"),
            uiText(
                m_settings,
                "Network Tools\n\n"
                "Назначение:\n"
                "Промышленная настольная утилита для IP-сканирования, HTTP-запросов, Serial, TCP, UDP, SSH, Telnet и SNMP Browser.\n\n"
                "Транспортные модули:\n"
                "Serial, TCP и UDP поддерживают как текстовый обмен, так и произвольные бинарные/HEX-последовательности, включая команды уровня VISCA и аналогичные протоколы управления.\n\n"
                "Безопасность и эксплуатация:\n"
                "Используйте только доверенные сетевые сегменты и подтвержденные учетные данные. Перед запуском в продуктивной среде проверьте сетевые политики, адреса, порты и сценарии автосканирования.\n\n"
                "Журналы обмена:\n"
                "Зеленая стрелка обозначает исходящую команду, синяя стрелка — входящий ответ. При включенном HEX данные отображаются в шестнадцатеричном виде как для передачи, так и для приема.",
                "Network Tools\n\n"
                "Purpose:\n"
                "A desktop utility for IP scanning, HTTP requests, Serial, TCP, UDP, SSH, and Telnet.\n\n"
                "Transport modules:\n"
                "Serial, TCP, and UDP support both text exchange and arbitrary binary / HEX payloads, including VISCA-level control commands and similar protocols.\n\n"
                "Safety and operation:\n"
                "Use only trusted network segments and verified credentials. Before running in production, verify network policies, addresses, ports, and auto-scan scenarios.\n\n"
                "Traffic logs:\n"
                "The green arrow marks outgoing commands, the blue arrow marks incoming responses. With HEX enabled, data is shown in hexadecimal form for both send and receive."
            )
        );
    });
    helpMenu->addAction(uiText(language, "О программе", "About"), this, [this]() {
        QMessageBox::information(
            this,
            uiText(m_settings, "О программе", "About"),
            QStringLiteral("Network Tools\nNative C++/Qt desktop utility for network diagnostics and transport control.")
        );
    });
}

void MainWindow::buildUi() {
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    configureMenuBar();

    m_pages = new QStackedWidget(central);
    m_pages->addWidget(createScanPage());
    m_pages->addWidget(createRequestPage());
    m_pages->addWidget(createSerialPage());
    m_pages->addWidget(createTcpPage());
    m_pages->addWidget(createUdpPage());
    m_pages->addWidget(createSessionPage(QStringLiteral("SSH"), m_sshWidgets, 22));
    m_pages->addWidget(createSessionPage(QStringLiteral("Telnet"), m_telnetWidgets, 23));
    m_pages->addWidget(createSnmpPage());
    root->addWidget(m_pages, 1);
    setCentralWidget(central);
    syncCurrentPage(0);
    refreshScanToolbarIcons();
    updateScanSortButton();

    connect(m_sshWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_sshSession->isConnected()) {
            m_sshSession->close();
            return;
        }
        m_sshWidgets.outputBox->clear();
        m_sshSession->open(currentSessionProfile(m_sshWidgets, 22));
    });
    connect(m_telnetWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_telnetSession->isConnected()) {
            m_telnetSession->close();
            return;
        }
        m_telnetWidgets.outputBox->clear();
        m_telnetSession->open(currentSessionProfile(m_telnetWidgets, 23));
    });
}

void MainWindow::syncCurrentPage(int row) {
    if (m_pages == nullptr || row < 0 || row >= m_pages->count()) {
        return;
    }
    m_pages->setCurrentIndex(row);
}

void MainWindow::openSettingsDialog() {
    const QString previousTheme = m_settings->theme();
    const QString previousLanguage = m_settings->language();
    const QString previousTerminalColor = m_settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"));
    const int previousAutoScanInterval = qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30));
    SettingsDialog dialog(m_settings, this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    if (previousTheme != m_settings->theme()) {
        applyDarkPalette();
        applyStyleSheet();
        refreshScanTableColors();
        refreshScanToolbarIcons();
    }
    if (previousLanguage != m_settings->language()) {
        QMessageBox::information(
            this,
            uiText(m_settings, "Настройки", "Settings"),
            uiText(m_settings, "Язык интерфейса сохранен. Перезапустите приложение.", "Interface language saved. Restart the application.")
        );
    }
    if (previousTerminalColor != m_settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"))) {
        refreshTerminalFormats();
    }
    const int updatedAutoScanInterval = qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30));
    if (previousAutoScanInterval != updatedAutoScanInterval && m_scanAutoScanTimer != nullptr) {
        m_scanAutoScanTimer->setInterval(updatedAutoScanInterval * 1000);
        if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked() && !m_scanAutoScanTimer->isActive()) {
            m_scanAutoScanTimer->start();
        }
    }
}

void MainWindow::reloadAdapters() {
    const auto list = m_scanner->adapters();
    const auto previous = m_scanAdapterCombo->currentData().toString();
    m_scanAdapterCombo->clear();
    for (const auto& adapter : list) {
        const auto range = rangeFromIpAndPrefix(adapter.ip, adapter.prefixLength);
        const QString label = QStringLiteral("%1 | %2").arg(adapter.name, adapter.network);
        m_scanAdapterCombo->addItem(label, adapter.id);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.first, Qt::UserRole + 1);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.second, Qt::UserRole + 2);
    }
    const int previousIndex = m_scanAdapterCombo->findData(previous);
    if (previousIndex >= 0) {
        m_scanAdapterCombo->setCurrentIndex(previousIndex);
    }
}

void MainWindow::applySuggestedRange() {
    const auto suggestion = m_scanner->suggestRange();
    const int index = m_scanAdapterCombo->findData(suggestion.adapterId);
    if (index >= 0) {
        m_scanAdapterCombo->setCurrentIndex(index);
    }
    if (m_scanAutoIpCheck != nullptr) {
        m_scanAutoIpCheck->setChecked(true);
    }
    if (m_scanAdapterCombo != nullptr && m_scanAdapterCombo->currentIndex() >= 0) {
        applyRangeFromCurrentAdapter();
    } else {
        m_scanStartIp->setText(suggestion.startIp);
        m_scanEndIp->setText(suggestion.endIp);
    }
    updateScanFooter(suggestion.label);
}

void MainWindow::applyRangeFromCurrentAdapter() {
    if (m_scanAdapterCombo == nullptr || m_scanAdapterCombo->currentIndex() < 0) {
        return;
    }
    nt::AdapterInfo adapter;
    const QString adapterId = m_scanAdapterCombo->currentData().toString();
    for (const auto& item : m_scanner->adapters()) {
        if (item.id == adapterId || item.name == adapterId) {
            adapter = item;
            break;
        }
    }
    if (adapter.ip.isEmpty()) {
        return;
    }
    bool ok = false;
    const QString prefixText = m_scanPrefixCombo != nullptr ? m_scanPrefixCombo->currentText() : QStringLiteral("/24");
    const int prefix = prefixText.mid(1).toInt(&ok);
    const auto range = rangeFromIpAndPrefix(adapter.ip, ok ? prefix : qMax(1, adapter.prefixLength));
    if (!range.first.isEmpty()) {
        m_scanStartIp->setText(range.first);
    }
    if (!range.second.isEmpty()) {
        m_scanEndIp->setText(range.second);
    }
}

void MainWindow::resolveHostnameRange() {
    applyRangeFromCurrentAdapter();
    updateScanFooter(uiText(m_settings, "Диапазон обновлен по адаптеру", "Range refreshed from adapter"));
}

void MainWindow::startScan() {
    if (m_scanner->isRunning() || m_scanLaunchPending) {
        return;
    }
    syncCurrentPage(0);
    ++m_currentScanGeneration;
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setText(uiText(m_settings, "■ Стоп", "■ Stop"));
        m_scanStartButton->setEnabled(true);
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(true);
    }
    if (m_scanAutoIpCheck != nullptr && m_scanAutoIpCheck->isChecked()) {
        applyRangeFromCurrentAdapter();
    }
    clearScanTable();
    m_scanRows.clear();
    m_scanNewIps.clear();
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(uiText(m_settings, "Онлайн: 0", "Online: 0"));
    }
    m_vendorDb->ensureReady(false);
    updateScanFooter(uiText(m_settings, "Сканирование...", "Scanning..."));
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, 0));
    }
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->repaint();
    }
    if (m_scanFooterStateLabel != nullptr) {
        m_scanFooterStateLabel->repaint();
    }
    qApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers);
    m_scanner->start(
        m_scanStartIp->text().trimmed(),
        m_scanEndIp->text().trimmed(),
        m_scanAdapterCombo->currentData().toString(),
        m_settings->scanWorkers(),
        m_currentScanGeneration
    );
}

void MainWindow::stopScan() {
    m_scanner->cancel();
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setEnabled(true);
        m_scanStartButton->setText(uiText(m_settings, "▶ Старт", "▶ Start"));
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(false);
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, m_scanRows.size()));
    }
    updateScanFooter(m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()
        ? uiText(m_settings, "Остановка сканирования... Авто скан активен", "Stopping scan... Auto scan is enabled")
        : uiText(m_settings, "Остановка сканирования...", "Stopping scan..."));
}

void MainWindow::saveSnapshot() {
    if (m_scanRows.isEmpty()) {
        QMessageBox::information(this, uiText(m_settings, "Снимки", "Snapshots"), uiText(m_settings, "Пока нет результатов сканирования для сохранения.", "There are no scan results to save yet."));
        return;
    }
    bool ok = false;
    const QString name = QInputDialog::getText(
        this,
        uiText(m_settings, "Сохранить снимок", "Save snapshot"),
        uiText(m_settings, "Название снимка", "Snapshot name"),
        QLineEdit::Normal,
        QStringLiteral("baseline"),
        &ok
    );
    if (!ok) {
        return;
    }
    QString path;
    QString error;
    if (!m_snapshots->saveSnapshot(name, m_scanRows, m_scanStartIp->text(), m_scanEndIp->text(), m_scanAdapterCombo->currentText(), &path, &error)) {
        QMessageBox::warning(this, uiText(m_settings, "Снимки", "Snapshots"), error);
        return;
    }
    refreshFavoritesMenu();
    updateScanFooter(uiText(m_settings, "Снимок сохранен: %1", "Snapshot saved: %1").arg(path));
}

void MainWindow::deleteSnapshot() {
    const auto snapshots = m_snapshots->listSnapshots();
    if (snapshots.isEmpty()) {
        QMessageBox::information(
            this,
            uiText(m_settings, "Удаление снимка", "Delete snapshot"),
            uiText(m_settings, "Сохраненных снимков пока нет.", "There are no saved snapshots yet.")
        );
        return;
    }

    QStringList options;
    for (const auto& item : snapshots) {
        options.append(uiText(m_settings, "%1 | %2 | хостов: %3", "%1 | %2 | hosts: %3").arg(item.name, item.createdAt.left(19), QString::number(item.rowCount)));
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(
        this,
        uiText(m_settings, "Удаление снимка", "Delete snapshot"),
        uiText(m_settings, "Выберите снимок", "Choose snapshot"),
        options,
        0,
        false,
        &ok
    );
    if (!ok || choice.isEmpty()) {
        return;
    }

    const int index = options.indexOf(choice);
    if (index < 0 || index >= snapshots.size()) {
        return;
    }

    const auto snapshot = snapshots.at(index);
    const auto answer = QMessageBox::question(
        this,
        uiText(m_settings, "Удаление снимка", "Delete snapshot"),
        uiText(m_settings, "Удалить снимок \"%1\"?", "Delete snapshot \"%1\"?").arg(snapshot.name),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );
    if (answer != QMessageBox::Yes) {
        return;
    }

    QString error;
    if (!m_snapshots->deleteSnapshot(snapshot.path, &error)) {
        QMessageBox::warning(this, uiText(m_settings, "Удаление снимка", "Delete snapshot"), error);
        return;
    }

    refreshFavoritesMenu();
    updateScanFooter(uiText(m_settings, "Снимок удален: %1", "Snapshot deleted: %1").arg(snapshot.name));
}

void MainWindow::compareSnapshot() {
    const auto snapshots = m_snapshots->listSnapshots();
    if (snapshots.isEmpty()) {
        QMessageBox::information(this, uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"), uiText(m_settings, "Сохраненных снимков пока нет.", "There are no saved snapshots yet."));
        return;
    }

    QStringList options;
    for (const auto& item : snapshots) {
        options.append(uiText(m_settings, "%1 | %2 | хостов: %3", "%1 | %2 | hosts: %3").arg(item.name, item.createdAt.left(19), QString::number(item.rowCount)));
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(
        this,
        uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"),
        uiText(m_settings, "Сохраненные снимки", "Saved snapshots"),
        options,
        0,
        false,
        &ok
    );
    if (!ok || choice.isEmpty()) {
        return;
    }
    const int index = options.indexOf(choice);
    if (index < 0 || index >= snapshots.size()) {
        return;
    }
    compareSnapshotPath(snapshots.at(index).path);
}

void MainWindow::compareSnapshotPath(const QString& path) {
    nt::SnapshotMeta meta;
    QString error;
    const auto rows = m_snapshots->loadSnapshotRows(path, &meta, &error);
    if (!error.isEmpty()) {
        QMessageBox::warning(this, uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"), error);
        return;
    }

    const auto summary = m_snapshots->diffRows(rows, m_scanRows);
    showSnapshotDiffDialog(meta, summary);
}

void MainWindow::refreshFavoritesMenu() {
    if (m_favoritesMenu == nullptr) {
        return;
    }
    m_favoritesMenu->clear();
    m_favoritesMenu->addAction(uiText(m_settings, "Сохранить текущий снимок", "Save current snapshot"), this, &MainWindow::saveSnapshot);
    m_favoritesMenu->addAction(uiText(m_settings, "Удалить снимок...", "Delete snapshot..."), this, &MainWindow::deleteSnapshot);
    m_favoritesMenu->addAction(uiText(m_settings, "Сравнить со снимком...", "Compare with snapshot..."), this, &MainWindow::compareSnapshot);
    auto* compareAction = m_favoritesMenu->addAction(uiText(m_settings, "Сравнение сканов", "Scan comparison"));
    compareAction->setCheckable(true);
    compareAction->setChecked(m_scanCompareMode);
    connect(compareAction, &QAction::toggled, this, &MainWindow::toggleScanCompareMode);
    const auto snapshots = m_snapshots->listSnapshots();
    m_favoritesMenu->addSeparator();
    if (snapshots.isEmpty()) {
        auto* emptyAction = m_favoritesMenu->addAction(uiText(m_settings, "Пока пусто", "Empty"));
        emptyAction->setEnabled(false);
        return;
    }
    for (const auto& snapshot : snapshots) {
        const QString label = QStringLiteral("%1 | %2 | %3").arg(snapshot.name, snapshot.createdAt.left(19), QString::number(snapshot.rowCount));
        m_favoritesMenu->addAction(label, this, [this, path = snapshot.path]() { compareSnapshotPath(path); });
    }
}

void MainWindow::showSnapshotDiffDialog(const nt::SnapshotMeta& meta, const nt::SnapshotDiffSummary& summary) {
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("Diff | %1").arg(meta.name));
    dialog->resize(980, 560);

    auto* root = new QVBoxLayout(dialog);
    auto* chips = new QHBoxLayout();

    const auto addChip = [chips](const QString& text, const QColor& color) {
        auto* label = new QLabel(text);
        label->setStyleSheet(QStringLiteral("QLabel { color:%1; font-weight:700; padding:2px 4px; }").arg(color.name()));
        chips->addWidget(label);
    };

    addChip(uiText(m_settings, "+ Добавлено: %1", "+ Added: %1").arg(summary.added), QColor("#6fd27f"));
    addChip(uiText(m_settings, "- Вышло: %1", "- Removed: %1").arg(summary.removed), QColor("#ef7b7b"));
    addChip(uiText(m_settings, "~ Изменено: %1", "~ Changed: %1").arg(summary.changed), QColor("#f2c36a"));
    chips->addStretch(1);
    root->addLayout(chips);

    auto* info = new QLabel(uiText(m_settings, "%1 | %2 | Хостов в снимке: %3", "%1 | %2 | Hosts in snapshot: %3").arg(meta.name, meta.createdAt.left(19), QString::number(meta.rowCount)), dialog);
    root->addWidget(info);

    auto* table = new QTableWidget(dialog);
    table->setColumnCount(5);
    table->setHorizontalHeaderLabels({
        uiText(m_settings, "Тип", "Type"),
        QStringLiteral("IP"),
        uiText(m_settings, "Было", "Before"),
        uiText(m_settings, "Стало", "After"),
        uiText(m_settings, "Детали", "Details"),
    });
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    table->setRowCount(summary.entries.size());

    for (int row = 0; row < summary.entries.size(); ++row) {
        const auto& entry = summary.entries.at(row);
        QString kindLabel;
        QColor fg;
        if (entry.kind == nt::SnapshotDiffKind::Added) {
            kindLabel = QStringLiteral("+ Added");
            fg = QColor("#6fd27f");
        } else if (entry.kind == nt::SnapshotDiffKind::Removed) {
            kindLabel = QStringLiteral("- Removed");
            fg = QColor("#ef7b7b");
        } else {
            kindLabel = QStringLiteral("~ Changed");
            fg = QColor("#f2c36a");
        }
        const QStringList columns {kindLabel, entry.ip, entry.beforeValue, entry.afterValue, entry.details};
        for (int col = 0; col < columns.size(); ++col) {
            auto* item = new QTableWidgetItem(columns.at(col));
            if (col == 0) {
                item->setForeground(fg);
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            }
            if (col == 4) {
                item->setToolTip(entry.details);
            }
            table->setItem(row, col, item);
        }
    }

    root->addWidget(table, 1);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    root->addWidget(buttons);
    dialog->show();
}

void MainWindow::clearScanTable() {
    m_scanTable->setRowCount(0);
    for (auto it = m_hostLabels.begin(); it != m_hostLabels.end(); ++it) {
        it.value()->setText(localizedMissingText(m_settings));
    }
}

void MainWindow::rebuildScanTable() {
    if (m_scanTable == nullptr) {
        return;
    }
    m_scanTable->setRowCount(0);
    QList<nt::ScanRecord> sortedRows = m_scanRows;
    std::sort(sortedRows.begin(), sortedRows.end(), [this](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        const quint32 leftIp = ipToInt(left.ip);
        const quint32 rightIp = ipToInt(right.ip);
        return m_scanSortAscending ? leftIp < rightIp : leftIp > rightIp;
    });
    for (const auto& record : sortedRows) {
        const nt::ScanRecord& safeRecord = record;
        if (safeRecord.ip.isEmpty()) {
            continue;
        }
        int rowIndex = findRowByIp(m_scanTable, safeRecord.ip);
        if (rowIndex < 0) {
            rowIndex = insertionRowForIp(m_scanTable, safeRecord.ip, m_scanSortAscending);
            m_scanTable->insertRow(rowIndex);
        }

        const QList<QString> values = {
            safeRecord.ip,
            displayCellValue(m_settings, safeRecord.pingDisplay, QStringLiteral("[n/a]")),
            displayCellValue(m_settings, safeRecord.mac, QStringLiteral("-")),
            displayCellValue(m_settings, safeRecord.vendor, QStringLiteral("unknown vendor")),
            normalizedHostNameText(m_settings, safeRecord.hostName),
            normalizedWebDetectText(m_settings, safeRecord.webDetect),
            displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-")),
            scanPortCellText(m_settings, safeRecord.port),
            normalizedTypeText(m_settings, safeRecord.typeHint),
        };
        const QString gatewayValue = displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-"));
        const bool isGatewayHost = gatewayValue != localizedMissingText(m_settings) && safeRecord.ip == gatewayValue;
        const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
        const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
        const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
        const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");
        const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(safeRecord.ip);

        for (int col = 0; col < values.size(); ++col) {
            auto* item = m_scanTable->item(rowIndex, col);
            if (item == nullptr) {
                item = new QTableWidgetItem();
                m_scanTable->setItem(rowIndex, col, item);
            }
            item->setText(values.at(col));
            item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
            if (col == ScanColumnType) {
                item->setData(Qt::UserRole, normalizedTypeText(m_settings, safeRecord.typeHint));
                item->setText(scanTypeCellText(m_settings, safeRecord.typeHint, isNewHost));
                item->setTextAlignment(Qt::AlignCenter);
                item->setToolTip(item->text());
            }
            if (col == ScanColumnWeb) {
                item->setToolTip(item->text());
            }
            if (col == ScanColumnPort || col == ScanColumnWeb || col == ScanColumnType) {
                item->setTextAlignment(Qt::AlignCenter);
            }
            if (col == ScanColumnType && isNewHost) {
                item->setForeground(QBrush(QColor("#7fda72")));
            } else {
                item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
            }
            QFont font = item->font();
            font.setBold(isGatewayHost || (col == ScanColumnType && isNewHost));
            item->setFont(font);
            if (col == ScanColumnIp) {
                item->setIcon(statusOrb(safeRecord.status));
                item->setToolTip(
                    uiText(m_settings, "Статус: %1\nMAC: %2\nВендор: %3\nHostname: %4\nWeb: %5\nШлюз IP: %6\nОткрытые порты: %7\nТип: %8\nМаршрут: %9\nМаска: %10%11",
                           "Status: %1\nMAC: %2\nVendor: %3\nHostname: %4\nWeb: %5\nGateway IP: %6\nOpen ports: %7\nType: %8\nRoute: %9\nMask: %10%11")
                        .arg(localizedHostStatusText(m_settings, safeRecord.status))
                        .arg(displayCellValue(m_settings, safeRecord.mac, QStringLiteral("-")))
                        .arg(displayCellValue(m_settings, safeRecord.vendor, QStringLiteral("unknown vendor")))
                        .arg(normalizedHostNameText(m_settings, safeRecord.hostName))
                        .arg(normalizedWebDetectText(m_settings, safeRecord.webDetect))
                        .arg(displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-")))
                        .arg(scanPortCellText(m_settings, safeRecord.port))
                        .arg(normalizedTypeText(m_settings, safeRecord.typeHint))
                        .arg(displayCellValue(m_settings, safeRecord.name, QStringLiteral("-")))
                        .arg(displayCellValue(m_settings, safeRecord.mask, QStringLiteral("-")))
                        .arg(isGatewayHost ? uiText(m_settings, "\nУзел является шлюзом сети.", "\nThis host is the network gateway.") : QString())
                );
            }
        }
    }
    applyScanColumnVisibility();
    refreshScanComparisonBadges();
    applyScanTableFilter();
}

void MainWindow::applyScanTableFilter() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QString needle = m_scanFilterEdit == nullptr ? QString() : m_scanFilterEdit->text().trimmed().toLower();
    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        const auto* ipItem = m_scanTable->item(row, ScanColumnIp);
        if (ipItem == nullptr) {
            continue;
        }
        const QString ip = ipItem->text();
        const auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
            return record.ip == ip;
        });
        const bool visible = it != m_scanRows.end() ? scanRecordMatchesFilter(*it, needle) : needle.isEmpty();
        m_scanTable->setRowHidden(row, !visible);
    }
}

void MainWindow::applyScanColumnVisibility() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QJsonObject saved = m_settings->section(QStringLiteral("scan_columns"));
    for (int column = 0; column < ScanColumnCount; ++column) {
        auto* action = m_scanColumnActions.value(column, nullptr);
        bool visible = scanColumnVisibleByDefault(column);
        if (saved.contains(scanColumnKey(column))) {
            visible = saved.value(scanColumnKey(column)).toBool(visible);
        } else if (action != nullptr) {
            visible = action->isChecked();
        }
        if (column == ScanColumnIp) {
            visible = true;
        }
        if (action != nullptr && action->isChecked() != visible) {
            QSignalBlocker blocker(action);
            action->setChecked(visible);
        }
        m_scanTable->setColumnHidden(column, !visible);
    }
}

void MainWindow::saveScanColumnVisibility() const {
    QJsonObject section;
    for (int column = 0; column < ScanColumnCount; ++column) {
        const auto* action = m_scanColumnActions.value(column, nullptr);
        section.insert(scanColumnKey(column), column == ScanColumnIp ? true : (action != nullptr && action->isChecked()));
    }
    m_settings->setSection(QStringLiteral("scan_columns"), section);
    m_settings->save();
}

void MainWindow::updateScanSortButton() {
    if (m_scanSortButton == nullptr) {
        return;
    }
    m_scanSortButton->setText(m_scanSortAscending ? QStringLiteral("\u2191") : QStringLiteral("\u2193"));
    m_scanSortButton->setToolTip(
        m_scanSortAscending
            ? uiText(m_settings, "Сортировка по IP: по возрастанию", "IP sort: ascending")
            : uiText(m_settings, "Сортировка по IP: по убыванию", "IP sort: descending")
    );
}

void MainWindow::toggleScanSortOrder() {
    m_scanSortAscending = !m_scanSortAscending;
    updateScanSortButton();
    rebuildScanTable();
}

void MainWindow::refreshScanToolbarIcons() {
    if (m_scanToolsButton == nullptr) {
        return;
    }
    const QColor iconColor = isLightTheme() ? QColor("#5f6a76") : QColor("#c1ccd8");
    m_scanToolsButton->setIcon(scanGearIcon(iconColor));
    m_scanToolsButton->setIconSize(QSize(18, 18));
}

int MainWindow::findRowByIp(QTableWidget* table, const QString& ip) {
    for (int row = 0; row < table->rowCount(); ++row) {
        const auto* item = table->item(row, 0);
        if (item != nullptr && item->text() == ip) {
            return row;
        }
    }
    return -1;
}

void MainWindow::appendScanRecord(const nt::ScanRecord& record) {
    if (record.ip.isEmpty() || record.generation != m_currentScanGeneration) {
        return;
    }

    bool updated = false;
    for (auto& existing : m_scanRows) {
        if (existing.ip == record.ip) {
            existing = record;
            updated = true;
            break;
        }
    }
    if (!updated) {
        m_scanRows.append(record);
    }
    if (m_scanCompareMode && m_scanCompareHasBaseline && !m_scanComparisonBaseline.contains(record.ip)) {
        m_scanNewIps.insert(record.ip);
    }

    int rowIndex = findRowByIp(m_scanTable, record.ip);
    if (rowIndex < 0) {
        rowIndex = insertionRowForIp(m_scanTable, record.ip, m_scanSortAscending);
        m_scanTable->insertRow(rowIndex);
    }

    const QList<QString> values = {
        record.ip,
        displayCellValue(m_settings, record.pingDisplay, QStringLiteral("[n/a]")),
        displayCellValue(m_settings, record.mac, QStringLiteral("-")),
        displayCellValue(m_settings, record.vendor, QStringLiteral("unknown vendor")),
        normalizedHostNameText(m_settings, record.hostName),
        normalizedWebDetectText(m_settings, record.webDetect),
        displayCellValue(m_settings, record.gateway, QStringLiteral("-")),
        scanPortCellText(m_settings, record.port),
        normalizedTypeText(m_settings, record.typeHint),
    };
    const QString gatewayValue = displayCellValue(m_settings, record.gateway, QStringLiteral("-"));
    const bool isGatewayHost = gatewayValue != localizedMissingText(m_settings) && record.ip == gatewayValue;
    const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");
    const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(record.ip);

    for (int col = 0; col < values.size(); ++col) {
        auto* item = m_scanTable->item(rowIndex, col);
        if (item == nullptr) {
            item = new QTableWidgetItem();
            m_scanTable->setItem(rowIndex, col, item);
        }
        item->setText(values.at(col));
        item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
        if (col == ScanColumnType) {
            item->setData(Qt::UserRole, normalizedTypeText(m_settings, record.typeHint));
            item->setText(scanTypeCellText(m_settings, record.typeHint, isNewHost));
            item->setTextAlignment(Qt::AlignCenter);
            item->setToolTip(item->text());
        }
        if (col == ScanColumnWeb) {
            item->setToolTip(item->text());
        }
        if (col == ScanColumnPort || col == ScanColumnWeb || col == ScanColumnType) {
            item->setTextAlignment(Qt::AlignCenter);
        }
        if (col == ScanColumnType && isNewHost) {
            item->setForeground(QBrush(QColor("#7fda72")));
        } else {
            item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
        }
        QFont font = item->font();
        font.setBold(isGatewayHost || (col == ScanColumnType && isNewHost));
        item->setFont(font);
        if (col == ScanColumnIp) {
            item->setIcon(statusOrb(record.status));
            item->setToolTip(
                uiText(m_settings, "Статус: %1\nMAC: %2\nВендор: %3\nHostname: %4\nWeb: %5\nШлюз IP: %6\nОткрытые порты: %7\nТип: %8\nМаршрут: %9\nМаска: %10%11",
                       "Status: %1\nMAC: %2\nVendor: %3\nHostname: %4\nWeb: %5\nGateway IP: %6\nOpen ports: %7\nType: %8\nRoute: %9\nMask: %10%11")
                    .arg(localizedHostStatusText(m_settings, record.status))
                    .arg(displayCellValue(m_settings, record.mac, QStringLiteral("-")))
                    .arg(displayCellValue(m_settings, record.vendor, QStringLiteral("unknown vendor")))
                    .arg(normalizedHostNameText(m_settings, record.hostName))
                    .arg(normalizedWebDetectText(m_settings, record.webDetect))
                    .arg(displayCellValue(m_settings, record.gateway, QStringLiteral("-")))
                    .arg(scanPortCellText(m_settings, record.port))
                    .arg(normalizedTypeText(m_settings, record.typeHint))
                    .arg(displayCellValue(m_settings, record.name, QStringLiteral("-")))
                    .arg(displayCellValue(m_settings, record.mask, QStringLiteral("-")))
                    .arg(isGatewayHost ? uiText(m_settings, "\nУзел является шлюзом сети.", "\nThis host is the network gateway.") : QString())
            );
        }
    }

    updateScanSummary();
    refreshScanComparisonBadges();
    applyScanTableFilter();
}

void MainWindow::finalizeScan(const QList<nt::ScanRecord>& records, int durationMs) {
    if (!records.isEmpty() && records.first().generation != m_currentScanGeneration) {
        return;
    }
    QList<nt::ScanRecord> sortedRecords = records;
    std::sort(sortedRecords.begin(), sortedRecords.end(), [this](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        const quint32 leftIp = ipToInt(left.ip);
        const quint32 rightIp = ipToInt(right.ip);
        return m_scanSortAscending ? leftIp < rightIp : leftIp > rightIp;
    });
    m_scanRows = sortedRecords;
    rebuildScanTable();
    if (m_scanTable != nullptr) {
        m_scanTable->viewport()->update();
    }
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setEnabled(true);
        m_scanStartButton->setText(uiText(m_settings, "▶ Старт", "▶ Start"));
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(false);
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, m_scanRows.size()));
    }
    if (m_scanCompareMode) {
        QSet<QString> currentIps;
        for (const auto& record : m_scanRows) {
            currentIps.insert(record.ip);
        }
        if (!m_scanCompareHasBaseline) {
            m_scanNewIps.clear();
            m_scanCompareHasBaseline = true;
        } else {
            m_scanNewIps = currentIps - m_scanComparisonBaseline;
        }
        m_scanComparisonBaseline = currentIps;
        refreshScanComparisonBadges();
    } else {
        m_scanComparisonBaseline.clear();
        m_scanNewIps.clear();
        m_scanCompareHasBaseline = false;
        refreshScanComparisonBadges();
    }
    updateScanSummary();
    updateSelectedHostPanel();
    updateScanFooter(localizedScanFinishedText(m_settings, durationMs));
}

void MainWindow::updateScanSummary() {
    int online = 0;
    int offline = 0;
    int detected = 0;
    int macCount = 0;
    for (const auto& row : m_scanRows) {
        if (row.status == nt::HostStatus::Online) {
            ++online;
            ++detected;
        } else if (row.status == nt::HostStatus::Unknown) {
            ++detected;
        } else if (row.status == nt::HostStatus::Offline) {
            ++offline;
        }
        if (!row.mac.trimmed().isEmpty() && row.mac != QStringLiteral("-")) {
            ++macCount;
        }
    }
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(
            isEnglishUi(m_settings)
                ? QStringLiteral("Online: %1").arg(online)
                : QStringLiteral("Онлайн: %1").arg(online)
        );
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, m_scanRows.size()));
    }
    if (m_scanFooterStateLabel != nullptr && !m_scanner->isRunning()) {
        updateScanFooter(localizedScanSummaryText(m_settings, m_scanRows.size(), online, macCount));
    }
}

void MainWindow::updateScanFooter(const QString& stateText) {
    if (m_scanFooterStateLabel != nullptr && !stateText.isEmpty()) {
        m_scanFooterStateLabel->setText(stateText);
        const bool comparisonAccent = stateText == localizedComparisonModeText(m_settings);
        if (comparisonAccent) {
            m_scanFooterStateLabel->setStyleSheet(QStringLiteral(
                "QLabel#statusCell { color:#f2c36a; font-weight:700; background:transparent; border:none; padding:3px 7px; font-size:11px; }"
            ));
        } else {
            m_scanFooterStateLabel->setStyleSheet(QString());
        }
    }
}

void MainWindow::updateSelectedHostPanel() {
    if (m_hostLabels.isEmpty()) {
        return;
    }
    const int row = m_scanTable->currentRow();
    if (row < 0) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr) {
        return;
    }
    const QString selectedIp = ipItem->text();
    auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
        return record.ip == selectedIp;
    });
    if (it == m_scanRows.end()) {
        return;
    }
    const auto& item = *it;
    m_hostLabels.value(QStringLiteral("ip"))->setText(item.ip);
    m_hostLabels.value(QStringLiteral("status"))->setText(localizedHostStatusIndicator(m_settings, item.status));
    m_hostLabels.value(QStringLiteral("mac"))->setText(displayCellValue(m_settings, item.mac, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("vendor"))->setText(displayCellValue(m_settings, item.vendor, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("type"))->setText(normalizedTypeText(m_settings, item.typeHint));
    m_hostLabels.value(QStringLiteral("name"))->setText(displayCellValue(m_settings, item.name, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("gateway"))->setText(displayCellValue(m_settings, item.gateway, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("mask"))->setText(displayCellValue(m_settings, item.mask, QStringLiteral("-")));
}

void MainWindow::toggleScanCompareMode(bool enabled) {
    m_scanCompareMode = enabled;
    m_scanComparisonBaseline.clear();
    m_scanNewIps.clear();
    m_scanCompareHasBaseline = false;
    refreshFavoritesMenu();
    refreshScanComparisonBadges();
    if (enabled) {
        updateScanFooter(localizedComparisonModeText(m_settings));
        return;
    }
    if (m_scanner != nullptr && m_scanner->isRunning()) {
        updateScanFooter(uiText(m_settings, "Сканирование...", "Scanning..."));
    } else {
        updateScanSummary();
    }
}

void MainWindow::refreshScanComparisonBadges() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");

    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        const auto* ipItem = m_scanTable->item(row, ScanColumnIp);
        const auto* gatewayItem = m_scanTable->item(row, ScanColumnGateway);
        auto* badgeItem = m_scanTable->item(row, ScanColumnType);
        if (ipItem == nullptr || badgeItem == nullptr) {
            continue;
        }
        const QString ip = ipItem->text();
        const bool isGatewayHost = gatewayItem != nullptr
            && !gatewayItem->text().trimmed().isEmpty()
            && gatewayItem->text() != localizedMissingText(m_settings)
            && gatewayItem->text() == ip;
        const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(ip);
        badgeItem->setText(scanTypeCellText(m_settings, badgeItem->data(Qt::UserRole).toString(), isNewHost));
        badgeItem->setTextAlignment(Qt::AlignCenter);
        badgeItem->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
        badgeItem->setForeground(QBrush(isNewHost ? QColor("#7fda72") : (isGatewayHost ? gatewayForeground : defaultForeground)));
        badgeItem->setToolTip(badgeItem->text());
        QFont font = badgeItem->font();
        font.setBold(isGatewayHost || isNewHost);
        badgeItem->setFont(font);
    }
    m_scanTable->viewport()->update();
}

void MainWindow::openScanContextMenu(const QPoint& position) {
    if (m_scanTable == nullptr) {
        return;
    }
    const QModelIndex index = m_scanTable->indexAt(position);
    if (!index.isValid()) {
        return;
    }
    m_scanTable->selectRow(index.row());

    QMenu menu(this);
    auto* browserAction = menu.addAction(uiText(m_settings, "Открыть в браузере", "Open in browser"));
    auto* pingAction = menu.addAction(uiText(m_settings, "Ping", "Ping"));
    menu.addSeparator();
    auto* sshAction = menu.addAction(uiText(m_settings, "Connect SSH", "Connect SSH"));
    auto* telnetAction = menu.addAction(uiText(m_settings, "Connect Telnet", "Connect Telnet"));

    QAction* selected = menu.exec(m_scanTable->viewport()->mapToGlobal(position));
    if (selected == browserAction) {
        openScanRowInBrowser(index.row());
    } else if (selected == pingAction) {
        openScanRowPing(index.row());
    } else if (selected == sshAction) {
        openScanRowSession(QStringLiteral("ssh"), index.row());
    } else if (selected == telnetAction) {
        openScanRowSession(QStringLiteral("telnet"), index.row());
    }
}

void MainWindow::openScanRowInBrowser(int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || ipItem->text().trimmed().isEmpty()) {
        return;
    }
    const QString ip = ipItem->text().trimmed();
    QString targetUrl;
    const auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
        return record.ip == ip;
    });
    if (it != m_scanRows.end()) {
        targetUrl = firstServiceUrl(it->webDetect);
    }
    if (targetUrl.isEmpty()) {
        targetUrl = QStringLiteral("http://%1").arg(ip);
    }
    QDesktopServices::openUrl(QUrl::fromUserInput(targetUrl));
}

void MainWindow::openScanRowPing(int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || ipItem->text().trimmed().isEmpty()) {
        return;
    }
    if (!openPingInTerminal(ipItem->text().trimmed())) {
        QMessageBox::warning(this, uiText(m_settings, "Ping", "Ping"), uiText(m_settings, "Не удалось открыть терминал для ping.", "Failed to open terminal for ping."));
    }
}

void MainWindow::openScanRowSession(const QString& kind, int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || ipItem->text().trimmed().isEmpty()) {
        return;
    }
    const QString ip = ipItem->text().trimmed();
    if (kind == QStringLiteral("ssh")) {
        prepareSessionFromScan(m_sshWidgets, ip, 22, QStringLiteral("SSH"), 5);
    } else {
        prepareSessionFromScan(m_telnetWidgets, ip, 23, QStringLiteral("Telnet"), 6);
    }
}

void MainWindow::prepareSessionFromScan(SessionWidgets& widgets, const QString& host, quint16 port, const QString& kindLabel, int pageIndex) {
    if (host.trimmed().isEmpty()) {
        return;
    }
    if (pageIndex == 5 && m_sshSession->isConnected()) {
        m_sshSession->close();
    } else if (pageIndex == 6 && m_telnetSession->isConnected()) {
        m_telnetSession->close();
    }
    if (m_navList != nullptr) {
        m_navList->setCurrentRow(pageIndex);
    } else {
        syncCurrentPage(pageIndex);
    }
    widgets.nameEdit->setText(QStringLiteral("%1 %2").arg(kindLabel, host));
    widgets.hostEdit->setText(host);
    widgets.portSpin->setValue(port);
    widgets.userEdit->clear();
    widgets.passEdit->clear();
    if (widgets.outputBox != nullptr) {
        widgets.outputBox->clear();
    }
    if (widgets.statusLabel != nullptr) {
        widgets.statusLabel->setText(uiText(m_settings, "Не подключено", "Not connected"));
    }
    if (widgets.connectButton != nullptr) {
        widgets.connectButton->setText(localizedConnectText(m_settings, false));
    }
    if (widgets.userEdit != nullptr) {
        widgets.userEdit->setFocus();
        widgets.userEdit->selectAll();
    }
}

void MainWindow::sendHttpRequest() {
    if (m_requestUrlEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("HTTP / REQ"), uiText(m_settings, "Поле URL пустое.", "URL field is empty."));
        return;
    }

    bool parseFailed = false;
    auto parseObject = [this, &parseFailed](QPlainTextEdit* edit, const QString& title, bool allowEmpty = true) -> QJsonObject {
        QJsonParseError error;
        const QByteArray data = edit->toPlainText().trimmed().toUtf8();
        if (data.isEmpty() && allowEmpty) {
            return {};
        }
        const auto document = QJsonDocument::fromJson(data, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            parseFailed = true;
            QMessageBox::warning(
                this,
                QStringLiteral("HTTP / REQ"),
                uiText(m_settings, "%1 должны быть JSON-объектом.", "%1 must be a JSON object.").arg(title)
            );
            return {};
        }
        return document.object();
    };

    nt::HttpRequestSpec spec;
    spec.method = m_requestMethodCombo->currentText();
    spec.url = m_requestUrlEdit->text().trimmed();
    if (!spec.url.contains(QRegularExpression(QStringLiteral("^[a-zA-Z][a-zA-Z0-9+.-]*://")))) {
        spec.url.prepend(QStringLiteral("http://"));
    }
    spec.headers = parseObject(m_requestHeadersEdit, uiText(m_settings, "Заголовки", "Headers"));
    spec.params = parseObject(m_requestParamsEdit, uiText(m_settings, "Параметры", "Params"));
    if (parseFailed) {
        return;
    }
    spec.body = m_requestBodyEdit->toPlainText().toUtf8();
    spec.username = m_requestUserEdit->text().trimmed();
    spec.password = m_requestPassEdit->text();
    spec.timeoutSec = m_requestTimeoutSpin->value();

    QTextCursor cursor(m_requestResponseEdit->document());
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat textFormat;
    textFormat.setFont(fixedFont());
    textFormat.setForeground(isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6"));

    cursor.insertText(QStringLiteral("Network Tools -> %1 [%2]\n").arg(spec.url, spec.method.toUpper()), textFormat);
    m_requestResponseEdit->setTextCursor(cursor);
    m_requestResponseEdit->ensureCursorVisible();

    QJsonArray history = m_settings->value(QStringLiteral("http_history"), QJsonArray{}).toArray();
    QJsonObject item {
        {QStringLiteral("method"), spec.method.toUpper()},
        {QStringLiteral("url"), spec.url},
        {QStringLiteral("headers"), m_requestHeadersEdit->toPlainText()},
        {QStringLiteral("params"), m_requestParamsEdit->toPlainText()},
        {QStringLiteral("body"), m_requestBodyEdit->toPlainText()},
        {QStringLiteral("username"), spec.username},
        {QStringLiteral("timeout"), spec.timeoutSec},
    };
    QJsonArray compacted;
    compacted.append(item);
    for (const auto& value : history) {
        if (!value.isObject()) {
            continue;
        }
        const auto object = value.toObject();
        if (object.value(QStringLiteral("method")).toString() == item.value(QStringLiteral("method")).toString()
            && object.value(QStringLiteral("url")).toString() == item.value(QStringLiteral("url")).toString()
            && object.value(QStringLiteral("body")).toString() == item.value(QStringLiteral("body")).toString()) {
            continue;
        }
        compacted.append(object);
        if (compacted.size() >= 40) {
            break;
        }
    }
    m_settings->setValue(QStringLiteral("http_history"), compacted);
    m_settings->save();
    m_http->send(spec);
}

void MainWindow::openHttpHistory() {
    const QJsonArray history = m_settings->value(QStringLiteral("http_history"), QJsonArray{}).toArray();
    if (history.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("HTTP History"), uiText(m_settings, "История запросов пока пуста.", "Request history is empty."));
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(uiText(m_settings, "История HTTP", "HTTP History"));
    dialog.resize(760, 440);

    auto* root = new QVBoxLayout(&dialog);
    auto* list = new QListWidget(&dialog);
    root->addWidget(list, 1);

    for (const auto& value : history) {
        if (!value.isObject()) {
            continue;
        }
        const auto object = value.toObject();
        const QString method = object.value(QStringLiteral("method")).toString();
        const QString url = object.value(QStringLiteral("url")).toString();
        auto* item = new QListWidgetItem(QStringLiteral("%1  %2").arg(method, url));
        item->setData(Qt::UserRole, object);
        item->setForeground(httpMethodColor(method));
        QFont font = item->font();
        font.setBold(true);
        item->setFont(font);
        list->addItem(item);
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto* applyButton = buttons->addButton(uiText(m_settings, "Повторить", "Reuse"), QDialogButtonBox::AcceptRole);
    root->addWidget(buttons);

    const auto applySelection = [this, list, &dialog]() {
        auto* item = list->currentItem();
        if (item == nullptr) {
            return;
        }
        const QJsonObject object = item->data(Qt::UserRole).toJsonObject();
        m_requestMethodCombo->setCurrentText(object.value(QStringLiteral("method")).toString(QStringLiteral("GET")));
        m_requestUrlEdit->setText(object.value(QStringLiteral("url")).toString());
        m_requestHeadersEdit->setPlainText(object.value(QStringLiteral("headers")).toString());
        m_requestParamsEdit->setPlainText(object.value(QStringLiteral("params")).toString());
        m_requestBodyEdit->setPlainText(object.value(QStringLiteral("body")).toString());
        m_requestUserEdit->setText(object.value(QStringLiteral("username")).toString());
        m_requestPassEdit->clear();
        m_requestTimeoutSpin->setValue(object.value(QStringLiteral("timeout")).toInt(10));
        dialog.accept();
    };

    connect(applyButton, &QPushButton::clicked, &dialog, applySelection);
    connect(list, &QListWidget::itemDoubleClicked, &dialog, [applySelection](QListWidgetItem*) { applySelection(); });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}

void MainWindow::refreshSerialPorts() {
    const QString current = m_serialWidgets.portCombo != nullptr ? m_serialWidgets.portCombo->currentData().toString() : QString();
    const QString preferred = current.isEmpty()
        ? m_settings->section(QStringLiteral("serial")).value(QStringLiteral("port_name")).toString()
        : current;
    if (m_serialWidgets.portCombo == nullptr) {
        return;
    }
    m_serialWidgets.portCombo->clear();
    auto ports = QSerialPortInfo::availablePorts();
    std::sort(ports.begin(), ports.end(), [](const auto& left, const auto& right) {
        const bool leftCu = left.portName().startsWith(QStringLiteral("cu."));
        const bool rightCu = right.portName().startsWith(QStringLiteral("cu."));
        if (leftCu != rightCu) {
            return leftCu;
        }
        return left.portName().toLower() < right.portName().toLower();
    });
    if (ports.isEmpty()) {
        m_serialWidgets.portCombo->addItem(uiText(m_settings, "(портов нет)", "(no ports)"), QString());
        return;
    }
    for (const auto& port : ports) {
        const QString label = QStringLiteral("%1 - %2").arg(port.portName(), port.description().trimmed().isEmpty() ? port.portName() : port.description());
        m_serialWidgets.portCombo->addItem(label, port.portName());
    }
    const int index = m_serialWidgets.portCombo->findData(preferred);
    m_serialWidgets.portCombo->setCurrentIndex(index >= 0 ? index : 0);
}

void MainWindow::toggleSerial() {
    if (m_serialSession->isOpen()) {
        m_serialSession->close();
        return;
    }
    const QString portName = m_serialWidgets.portCombo->currentData().toString();
    if (portName.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Serial"), uiText(m_settings, "Порт не выбран.", "Port is not selected."));
        return;
    }
    QString error;
    const bool ok = m_serialSession->open(
        portName,
        m_serialWidgets.baudCombo->currentText().toInt(),
        m_serialWidgets.bitsCombo->currentText().toInt(),
        comboValue(m_serialWidgets.parityCombo),
        m_serialWidgets.stopBitsCombo->currentText(),
        comboValue(m_serialWidgets.flowControlCombo),
        &error
    );
    if (!ok) {
        QMessageBox::critical(this, QStringLiteral("Serial"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("serial"));
    section.insert(QStringLiteral("port_name"), portName);
    section.insert(QStringLiteral("baud"), m_serialWidgets.baudCombo->currentText());
    section.insert(QStringLiteral("data_bits"), m_serialWidgets.bitsCombo->currentText());
    section.insert(QStringLiteral("parity"), comboValue(m_serialWidgets.parityCombo));
    section.insert(QStringLiteral("stop_bits"), m_serialWidgets.stopBitsCombo->currentText());
    section.insert(QStringLiteral("flow_control"), comboValue(m_serialWidgets.flowControlCombo));
    m_settings->setSection(QStringLiteral("serial"), section);
    m_settings->save();
    appendTrafficEntry(
        m_serialWidgets.outputBox,
        QColor("#b0bac5"),
        QStringLiteral("INFO"),
        isEnglishUi(m_settings)
            ? QStringLiteral("Connected %1 @ %2").arg(portName, m_serialWidgets.baudCombo->currentText())
            : QStringLiteral("Подключено %1 @ %2").arg(portName, m_serialWidgets.baudCombo->currentText())
    );
}

void MainWindow::toggleTcp() {
    if (m_tcpSession->isConnected()) {
        m_tcpSession->close();
        return;
    }
    const QString host = m_tcpWidgets.hostEdit->text().trimmed();
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("TCP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    m_tcpWidgets.outputBox->clear();
    QString error;
    if (!m_tcpSession->open(
            host,
            static_cast<quint16>(m_tcpWidgets.portSpin->value()),
            static_cast<quint16>(m_tcpWidgets.localPortSpin->value()),
            m_tcpWidgets.noDelayCheck->isChecked(),
            m_tcpWidgets.keepAliveCheck->isChecked(),
            &error)) {
        QMessageBox::critical(this, QStringLiteral("TCP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("tcp"));
    section.insert(QStringLiteral("host"), host);
    section.insert(QStringLiteral("port"), m_tcpWidgets.portSpin->value());
    section.insert(QStringLiteral("local_port"), m_tcpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("no_delay"), m_tcpWidgets.noDelayCheck->isChecked());
    section.insert(QStringLiteral("keep_alive"), m_tcpWidgets.keepAliveCheck->isChecked());
    m_settings->setSection(QStringLiteral("tcp"), section);
    m_settings->save();
}

void MainWindow::toggleUdp() {
    if (m_udpSession->isOpen()) {
        m_udpSession->close();
        return;
    }
    QString error;
    if (!m_udpSession->bind(static_cast<quint16>(m_udpWidgets.localPortSpin->value()), m_udpWidgets.reuseAddressCheck->isChecked(), &error)) {
        QMessageBox::critical(this, QStringLiteral("UDP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("udp"));
    section.insert(QStringLiteral("host"), m_udpWidgets.hostEdit->text().trimmed());
    section.insert(QStringLiteral("remote_port"), m_udpWidgets.remotePortSpin->value());
    section.insert(QStringLiteral("local_port"), m_udpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("reuse_address"), m_udpWidgets.reuseAddressCheck->isChecked());
    m_settings->setSection(QStringLiteral("udp"), section);
    m_settings->save();
    appendTrafficEntry(
        m_udpWidgets.outputBox,
        QColor("#b0bac5"),
        QStringLiteral("INFO"),
        isEnglishUi(m_settings)
            ? QStringLiteral("UDP open :%1").arg(m_udpSession->localPort())
            : QStringLiteral("Открыт UDP :%1").arg(m_udpSession->localPort())
    );
}

QByteArray MainWindow::payloadFromText(const QString& text, bool hexEnabled) {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }
    if (trimmed.contains(QStringLiteral("\\x"))) {
        QByteArray payload;
        const auto matches = QRegularExpression(QStringLiteral("\\\\x([0-9a-fA-F]{2})")).globalMatch(trimmed);
        auto it = matches;
        while (it.hasNext()) {
            const auto match = it.next();
            bool ok = false;
            const auto value = match.captured(1).toUInt(&ok, 16);
            if (ok) {
                payload.append(static_cast<char>(value));
            }
        }
        if (!payload.isEmpty()) {
            return payload;
        }
    }
    if (hexEnabled) {
        QByteArray payload;
        const auto parts = trimmed.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        bool allHex = !parts.isEmpty();
        for (const auto& part : parts) {
            bool ok = false;
            const auto value = part.toUInt(&ok, 16);
            if (!ok || part.size() > 2) {
                allHex = false;
                break;
            }
            payload.append(static_cast<char>(value));
        }
        if (allHex) {
            return payload;
        }
    }
    return trimmed.toUtf8();
}

QString MainWindow::displayBytes(const QByteArray& bytes, bool hexEnabled) {
    if (hexEnabled) {
        return QString::fromUtf8(bytes.toHex(' '));
    }
    return nt::TerminalSanitizer::sanitize(bytes);
}

QByteArray MainWindow::applyLineEnding(QByteArray payload, const QString& eolName, bool hexEnabled) {
    if (hexEnabled) {
        return payload;
    }
    const QString eolKey = normalizedEolKey(eolName);
    if (eolKey == QStringLiteral("cr")) {
        payload.append('\r');
    } else if (eolKey == QStringLiteral("lf")) {
        payload.append('\n');
    } else if (eolKey == QStringLiteral("crlf")) {
        payload.append("\r\n");
    }
    return payload;
}

void MainWindow::appendTrafficEntry(QTextEdit* box, const QColor& arrowColor, const QString& direction, const QString& payload, const QString& endpoint) {
    if (box == nullptr || payload.isEmpty()) {
        return;
    }
    QTextCursor cursor(box->document());
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat arrowFormat;
    arrowFormat.setForeground(arrowColor);
    arrowFormat.setFont(fixedFont());
    arrowFormat.setFontWeight(QFont::Bold);

    QTextCharFormat textFormat;
    textFormat.setForeground(QColor("#eef2f6"));
    textFormat.setFont(fixedFont());

    QTextCharFormat metaFormat = textFormat;
    metaFormat.setForeground(QColor("#a7b2be"));

    cursor.insertText(QStringLiteral("➜ "), arrowFormat);
    cursor.insertText(direction, arrowFormat);
    if (!endpoint.isEmpty()) {
        cursor.insertText(QStringLiteral(" [%1]").arg(endpoint), metaFormat);
    }
    cursor.insertText(QStringLiteral("\n"), textFormat);
    cursor.insertText(payload, textFormat);
    cursor.insertText(QStringLiteral("\n\n"), textFormat);
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::loadQuickCommands(const QString& key, StreamWidgets& widgets) {
    const auto section = m_settings->section(key);
    const auto commands = section.value(QStringLiteral("quick_commands")).toArray();
    for (int i = 0; i < widgets.quickEdits.size(); ++i) {
        widgets.quickEdits[i]->setText(i < commands.size() ? commands.at(i).toString() : QString());
    }
    if (widgets.inputEdit != nullptr) {
        widgets.inputEdit->setText(section.value(QStringLiteral("draft")).toString());
    }
    if (widgets.eolCombo != nullptr) {
        setComboByData(widgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
}

void MainWindow::saveQuickCommands(const QString& key, const StreamWidgets& widgets) {
    auto section = m_settings->section(key);
    QJsonArray commands;
    for (auto* edit : widgets.quickEdits) {
        commands.append(edit == nullptr ? QString() : edit->text());
    }
    section.insert(QStringLiteral("quick_commands"), commands);
    if (widgets.inputEdit != nullptr) {
        section.insert(QStringLiteral("draft"), widgets.inputEdit->text());
    }
    if (widgets.eolCombo != nullptr) {
        section.insert(QStringLiteral("eol"), comboValue(widgets.eolCombo));
    }
    m_settings->setSection(key, section);
    m_settings->save();
}

void MainWindow::sendQuickCommand(const QString& key, StreamWidgets& widgets, int index) {
    if (index < 0 || index >= widgets.quickEdits.size() || widgets.inputEdit == nullptr) {
        return;
    }
    widgets.inputEdit->setText(widgets.quickEdits[index]->text());
    saveQuickCommands(key, widgets);
    if (key == QStringLiteral("serial")) {
        sendSerialPayload();
    } else if (key == QStringLiteral("tcp")) {
        sendTcpPayload();
    } else if (key == QStringLiteral("udp")) {
        sendUdpPayload();
    }
}

void MainWindow::sendSerialPayload() {
    QByteArray payload = payloadFromText(m_serialWidgets.inputEdit->text(), m_serialWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_serialWidgets.eolCombo), m_serialWidgets.hexCheck->isChecked());
    QString error;
    m_serialSession->sendBytes(payload, &error);
    if (!error.isEmpty()) {
        appendTrafficEntry(m_serialWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(m_serialWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_serialWidgets.hexCheck->isChecked()));
}

void MainWindow::sendTcpPayload() {
    QByteArray payload = payloadFromText(m_tcpWidgets.inputEdit->text(), m_tcpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    if (!m_tcpSession->isConnected()) {
        appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), uiText(m_settings, "TCP не подключен", "TCP is not connected"));
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_tcpWidgets.eolCombo), m_tcpWidgets.hexCheck->isChecked());
    m_tcpSession->sendBytes(payload);
    appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_tcpWidgets.hexCheck->isChecked()));
}

void MainWindow::sendUdpPayload() {
    QByteArray payload = payloadFromText(m_udpWidgets.inputEdit->text(), m_udpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_udpWidgets.eolCombo), m_udpWidgets.hexCheck->isChecked());
    QString error;
    m_udpSession->sendDatagram(
        m_udpWidgets.hostEdit->text().trimmed(),
        static_cast<quint16>(m_udpWidgets.remotePortSpin->value()),
        payload,
        &error
    );
    if (!error.isEmpty()) {
        appendTrafficEntry(m_udpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(
        m_udpWidgets.outputBox,
        QColor("#7fda72"),
        QStringLiteral("TX"),
        displayBytes(payload, m_udpWidgets.hexCheck->isChecked()),
        QStringLiteral("%1:%2").arg(m_udpWidgets.hostEdit->text().trimmed()).arg(m_udpWidgets.remotePortSpin->value())
    );
}

void MainWindow::sendSessionTerminalBytes(QTextEdit* box, const QByteArray& bytes) {
    if (bytes.isEmpty()) {
        return;
    }
    if (box == m_sshWidgets.outputBox) {
        m_sshSession->sendBytes(bytes);
        return;
    }
    if (box == m_telnetWidgets.outputBox) {
        QByteArray payload = bytes;
        payload.replace("\r\n", "\n");
        payload.replace('\r', '\n');
        payload.replace("\n", "\r\n");
        m_telnetSession->sendBytes(payload);
    }
}

void MainWindow::appendSessionTerminalOutput(QTextEdit* box, const QString& text) {
    if (box == nullptr || text.isEmpty()) {
        return;
    }
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (format == nullptr) {
        return;
    }
    const QTextCharFormat baseFormat = box == m_sshWidgets.outputBox ? m_sshTerminalBaseFormat : m_telnetTerminalBaseFormat;
    removeSessionDraft(box);
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    QString chunk;
    const auto flushChunk = [&]() {
        if (!chunk.isEmpty()) {
            cursor.insertText(chunk, *format);
            chunk.clear();
        }
    };
    for (int i = 0; i < text.size(); ++i) {
        const QChar ch = text.at(i);
        if (ch == QChar::fromLatin1('\x1b')) {
            flushChunk();
            if (i + 1 >= text.size()) {
                break;
            }
            const QChar next = text.at(i + 1);
            if (next == QLatin1Char(']')) {
                int j = i + 2;
                while (j < text.size()) {
                    if (text.at(j) == QChar::fromLatin1('\x07')) {
                        break;
                    }
                    if (text.at(j) == QChar::fromLatin1('\x1b') && j + 1 < text.size() && text.at(j + 1) == QLatin1Char('\\')) {
                        ++j;
                        break;
                    }
                    ++j;
                }
                i = j;
                continue;
            }
            if (next != QLatin1Char('[')) {
                continue;
            }
            int j = i + 2;
            while (j < text.size()) {
                const QChar final = text.at(j);
                if (final.unicode() >= '@' && final.unicode() <= '~') {
                    break;
                }
                ++j;
            }
            if (j >= text.size()) {
                break;
            }
            const QString params = text.mid(i + 2, j - (i + 2));
            const QChar final = text.at(j);
            if (final == QLatin1Char('m')) {
                QList<int> codes;
                const auto parts = params.split(QLatin1Char(';'));
                for (const auto& part : parts) {
                    bool ok = false;
                    const int value = part.isEmpty() ? 0 : part.toInt(&ok);
                    codes.append(ok || part.isEmpty() ? value : 0);
                }
                applyTerminalSgr(codes, *format, baseFormat);
            } else if (final == QLatin1Char('J')) {
                const int mode = params.isEmpty() ? 0 : params.toInt();
                if (mode == 2 || mode == 3) {
                    box->clear();
                    cursor = box->textCursor();
                    *format = baseFormat;
                }
            } else if (final == QLatin1Char('K')) {
                cursor.movePosition(QTextCursor::EndOfBlock, QTextCursor::KeepAnchor);
                cursor.removeSelectedText();
            }
            i = j;
            continue;
        }
        if (ch == QChar::fromLatin1('\r')) {
            flushChunk();
            cursor.movePosition(QTextCursor::End);
            cursor.movePosition(QTextCursor::StartOfBlock, QTextCursor::KeepAnchor);
            cursor.removeSelectedText();
            continue;
        }
        if (ch == QChar::fromLatin1('\b')) {
            flushChunk();
            cursor.deletePreviousChar();
            continue;
        }
        if (ch == QLatin1Char('\n')) {
            flushChunk();
            cursor.insertText(QStringLiteral("\n"), *format);
            continue;
        }
        if (ch == QLatin1Char('\t')) {
            chunk.append(QStringLiteral("    "));
            continue;
        }
        if (ch.unicode() < 0x20) {
            continue;
        }
        chunk.append(ch);
    }
    flushChunk();
    box->setTextCursor(cursor);
    renderSessionDraft(box);
    box->ensureCursorVisible();
}

void MainWindow::renderSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    int* draftCursor = sessionDraftCursorForBox(box);
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (box == nullptr || draft == nullptr || draftCursor == nullptr || format == nullptr) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText(*draft, *format);
    const int endPosition = cursor.position();
    cursor.setPosition(endPosition - (draft->size() - *draftCursor));
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::removeSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    if (box == nullptr || draft == nullptr || draft->isEmpty()) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.setPosition(cursor.position() - draft->size(), QTextCursor::KeepAnchor);
    cursor.removeSelectedText();
    box->setTextCursor(cursor);
}

QString* MainWindow::sessionDraftForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraft;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraft;
    }
    return nullptr;
}

int* MainWindow::sessionDraftCursorForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraftCursor;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraftCursor;
    }
    return nullptr;
}

QTextCharFormat* MainWindow::sessionTerminalFormatForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshTerminalFormat;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetTerminalFormat;
    }
    return nullptr;
}

nt::SessionProfile MainWindow::currentSnmpProfile() const {
    nt::SessionProfile profile;
    profile.host = m_snmpWidgets.hostEdit != nullptr ? m_snmpWidgets.hostEdit->text().trimmed() : QString();
    profile.port = m_snmpWidgets.portSpin != nullptr ? static_cast<quint16>(m_snmpWidgets.portSpin->value()) : 161;
    profile.protocolVersion = m_snmpWidgets.versionCombo != nullptr ? comboValue(m_snmpWidgets.versionCombo) : QStringLiteral("2c");
    profile.snmpReadCommunity = m_snmpWidgets.communityEdit != nullptr ? m_snmpWidgets.communityEdit->text().trimmed() : QString();
    profile.snmpWriteCommunity = m_snmpWidgets.writeCommunityEdit != nullptr ? m_snmpWidgets.writeCommunityEdit->text() : QString();
    profile.snmpV3User = m_snmpWidgets.v3UserEdit != nullptr ? m_snmpWidgets.v3UserEdit->text().trimmed() : QString();
    profile.snmpV3SecurityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr ? comboValue(m_snmpWidgets.v3SecurityLevelCombo) : QStringLiteral("noAuthNoPriv");
    profile.snmpV3AuthProtocol = m_snmpWidgets.v3AuthProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3AuthProtocolCombo) : QStringLiteral("SHA");
    profile.snmpV3AuthPassword = m_snmpWidgets.v3AuthPasswordEdit != nullptr ? m_snmpWidgets.v3AuthPasswordEdit->text() : QString();
    profile.snmpV3PrivacyProtocol = m_snmpWidgets.v3PrivacyProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3PrivacyProtocolCombo) : QStringLiteral("AES");
    profile.snmpV3PrivacyPassword = m_snmpWidgets.v3PrivacyPasswordEdit != nullptr ? m_snmpWidgets.v3PrivacyPasswordEdit->text() : QString();
    if (snmpUsesCommunity(profile.protocolVersion)) {
        profile.username = profile.snmpReadCommunity;
        profile.password = profile.snmpWriteCommunity;
    } else {
        profile.username = profile.snmpV3User;
        profile.password = profile.snmpV3AuthPassword;
    }
    if (profile.port == 0) {
        profile.port = 161;
    }
    profile.name = QStringLiteral("%1:%2").arg(profile.host, QString::number(profile.port));
    return profile;
}

void MainWindow::refreshSnmpVersionUi() {
    if (m_snmpWidgets.versionCombo == nullptr || m_snmpWidgets.securityStack == nullptr) {
        return;
    }
    const QString version = comboValue(m_snmpWidgets.versionCombo);
    const bool communityMode = snmpUsesCommunity(version);
    m_snmpWidgets.securityStack->setCurrentIndex(communityMode ? 0 : 1);

    const QString securityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr
        ? comboValue(m_snmpWidgets.v3SecurityLevelCombo)
        : QStringLiteral("noAuthNoPriv");
    const bool authEnabled = !communityMode && securityLevel != QStringLiteral("noAuthNoPriv");
    const bool privacyEnabled = !communityMode && securityLevel == QStringLiteral("authPriv");

    if (m_snmpWidgets.v3AuthProtocolCombo != nullptr) {
        m_snmpWidgets.v3AuthProtocolCombo->setEnabled(authEnabled);
    }
    if (m_snmpWidgets.v3AuthPasswordEdit != nullptr) {
        m_snmpWidgets.v3AuthPasswordEdit->setEnabled(authEnabled);
    }
    if (m_snmpWidgets.v3PrivacyProtocolCombo != nullptr) {
        m_snmpWidgets.v3PrivacyProtocolCombo->setEnabled(privacyEnabled);
    }
    if (m_snmpWidgets.v3PrivacyPasswordEdit != nullptr) {
        m_snmpWidgets.v3PrivacyPasswordEdit->setEnabled(privacyEnabled);
    }
    if (auto* currentPage = m_snmpWidgets.securityStack->currentWidget(); currentPage != nullptr) {
        const QSize targetSize = currentPage->sizeHint().expandedTo(QSize(0, 19));
        m_snmpWidgets.securityStack->setFixedWidth(targetSize.width());
        const int targetHeight = qMax(19, targetSize.height());
        m_snmpWidgets.securityStack->setFixedHeight(targetHeight);
    }
}

void MainWindow::applySnmpTableFilter() {
    if (m_snmpWidgets.table == nullptr) {
        return;
    }
    const QString needle = m_snmpWidgets.filterEdit == nullptr ? QString() : m_snmpWidgets.filterEdit->text().trimmed().toLower();
    for (int row = 0; row < m_snmpWidgets.table->rowCount(); ++row) {
        bool visible = needle.isEmpty();
        if (!visible) {
            QStringList parts;
            for (int column = 0; column < m_snmpWidgets.table->columnCount(); ++column) {
                const auto* item = m_snmpWidgets.table->item(row, column);
                if (item != nullptr) {
                    parts.append(item->text());
                }
            }
            visible = parts.join(QLatin1Char(' ')).toLower().contains(needle);
        }
        m_snmpWidgets.table->setRowHidden(row, !visible);
    }
}

void MainWindow::persistSnmpSettingsFromUi() {
    if (m_settings == nullptr) {
        return;
    }
    const nt::SessionProfile profile = currentSnmpProfile();
    auto section = m_settings->section(QStringLiteral("snmp"));
    section.insert(QStringLiteral("host"), profile.host);
    section.insert(QStringLiteral("port"), static_cast<int>(profile.port == 0 ? 161 : profile.port));
    section.insert(QStringLiteral("version"), profile.protocolVersion);
    section.insert(QStringLiteral("read_community"), profile.snmpReadCommunity);
    section.insert(QStringLiteral("write_community"), profile.snmpWriteCommunity);
    section.insert(QStringLiteral("v3_user"), profile.snmpV3User);
    section.insert(QStringLiteral("v3_security_level"), profile.snmpV3SecurityLevel);
    section.insert(QStringLiteral("v3_auth_protocol"), profile.snmpV3AuthProtocol);
    section.insert(QStringLiteral("v3_auth_password"), profile.snmpV3AuthPassword);
    section.insert(QStringLiteral("v3_privacy_protocol"), profile.snmpV3PrivacyProtocol);
    section.insert(QStringLiteral("v3_privacy_password"), profile.snmpV3PrivacyPassword);
    section.insert(QStringLiteral("base_oid"), QStringLiteral(".1"));
    m_settings->setSection(QStringLiteral("snmp"), section);
    m_settings->save();
}

QStringList MainWindow::currentSnmpAuthArgs(bool forWrite, QString* errorText) const {
    auto fail = [&](const QString& message) {
        if (errorText != nullptr) {
            *errorText = message;
        }
        return QStringList{};
    };

    if (m_snmpWidgets.versionCombo == nullptr) {
        return fail(uiText(m_settings, "SNMP-страница еще не инициализирована.", "SNMP page is not initialized yet."));
    }

    const QString version = comboValue(m_snmpWidgets.versionCombo);
    QStringList args {QStringLiteral("-v"), version};
    if (snmpUsesCommunity(version)) {
        const QString readCommunity = m_snmpWidgets.communityEdit != nullptr ? m_snmpWidgets.communityEdit->text().trimmed() : QString();
        const QString writeCommunity = m_snmpWidgets.writeCommunityEdit != nullptr ? m_snmpWidgets.writeCommunityEdit->text().trimmed() : QString();
        const QString community = forWrite && !writeCommunity.isEmpty() ? writeCommunity : readCommunity;
        if (community.isEmpty()) {
            return fail(
                forWrite
                    ? uiText(m_settings, "Укажите community для записи.", "Enter write community.")
                    : uiText(m_settings, "Укажите community для чтения.", "Enter read community.")
            );
        }
        args << QStringLiteral("-c") << community;
        return args;
    }

    const QString user = m_snmpWidgets.v3UserEdit != nullptr ? m_snmpWidgets.v3UserEdit->text().trimmed() : QString();
    const QString securityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr ? comboValue(m_snmpWidgets.v3SecurityLevelCombo) : QStringLiteral("noAuthNoPriv");
    const QString authProtocol = m_snmpWidgets.v3AuthProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3AuthProtocolCombo) : QStringLiteral("SHA");
    const QString authPassword = m_snmpWidgets.v3AuthPasswordEdit != nullptr ? m_snmpWidgets.v3AuthPasswordEdit->text() : QString();
    const QString privacyProtocol = m_snmpWidgets.v3PrivacyProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3PrivacyProtocolCombo) : QStringLiteral("AES");
    const QString privacyPassword = m_snmpWidgets.v3PrivacyPasswordEdit != nullptr ? m_snmpWidgets.v3PrivacyPasswordEdit->text() : QString();

    if (user.isEmpty()) {
        return fail(uiText(m_settings, "Укажите SNMPv3 user.", "Enter SNMPv3 user."));
    }

    args << QStringLiteral("-l") << securityLevel
         << QStringLiteral("-u") << user;

    if (securityLevel == QStringLiteral("authNoPriv") || securityLevel == QStringLiteral("authPriv")) {
        if (authPassword.trimmed().isEmpty()) {
            return fail(uiText(m_settings, "Укажите пароль аутентификации SNMPv3.", "Enter SNMPv3 authentication password."));
        }
        args << QStringLiteral("-a") << authProtocol
             << QStringLiteral("-A") << authPassword;
    }

    if (securityLevel == QStringLiteral("authPriv")) {
        if (privacyPassword.trimmed().isEmpty()) {
            return fail(uiText(m_settings, "Укажите пароль приватности SNMPv3.", "Enter SNMPv3 privacy password."));
        }
        args << QStringLiteral("-x") << privacyProtocol
             << QStringLiteral("-X") << privacyPassword;
    }

    return args;
}

void MainWindow::loadSnmpOidList() {
    if (m_snmpWidgets.hostEdit == nullptr || m_snmpWidgets.table == nullptr) {
        return;
    }

    const QString host = m_snmpWidgets.hostEdit->text().trimmed();
    const QString baseOid = QStringLiteral(".1");
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    QString authError;
    const QStringList authArgs = currentSnmpAuthArgs(false, &authError);
    if (authArgs.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), authError);
        return;
    }

    persistSnmpSettingsFromUi();

    if (m_snmpWidgets.statusLabel != nullptr) {
        m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
        m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Полный SNMP walk...", "Full SNMP walk..."));
    }
    if (m_snmpWidgets.loadButton != nullptr) {
        m_snmpWidgets.loadButton->setEnabled(false);
    }

    auto* process = new QProcess(this);
    QStringList args = authArgs;
    args << QStringLiteral("%1:%2").arg(host).arg(m_snmpWidgets.portSpin->value()) << baseOid;

    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError) {
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Не удалось запустить snmpwalk.", "Failed to start snmpwalk."));
        }
        process->deleteLater();
    });

    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this, process, baseOid](int exitCode, QProcess::ExitStatus exitStatus) {
        const QString stdOut = QString::fromUtf8(process->readAllStandardOutput());
        const QString stdErr = QString::fromUtf8(process->readAllStandardError()).trimmed();
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }

        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
                m_snmpWidgets.statusLabel->setText(stdErr.isEmpty()
                    ? uiText(m_settings, "SNMP-опрос завершился с ошибкой.", "SNMP walk failed.")
                    : stdErr);
            }
            process->deleteLater();
            return;
        }

        const QStringList lines = stdOut.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
        m_snmpTablePopulating = true;
        m_snmpWidgets.table->setRowCount(0);
        int inserted = 0;
        for (const QString& line : lines) {
            const auto parsed = parseSnmpLine(line);
            if (!parsed.valid) {
                continue;
            }
            const int row = m_snmpWidgets.table->rowCount();
            m_snmpWidgets.table->insertRow(row);

            auto* oidItem = new QTableWidgetItem(parsed.oid);
            oidItem->setFlags(oidItem->flags() & ~Qt::ItemIsEditable);
            oidItem->setToolTip(parsed.oid);

            const QString objectDescription = snmpObjectDescription(parsed.oid);
            auto* descItem = new QTableWidgetItem(describeOidLabel(m_settings, parsed.oid));
            descItem->setFlags(descItem->flags() & ~Qt::ItemIsEditable);
            if (!objectDescription.isEmpty()) {
                descItem->setToolTip(objectDescription);
            }

            auto* typeItem = new QTableWidgetItem(snmpTypeDisplayText(parsed.rawType));
            typeItem->setData(Qt::UserRole, parsed.rawType);
            typeItem->setFlags(typeItem->flags() & ~Qt::ItemIsEditable);
            typeItem->setTextAlignment(Qt::AlignCenter);
            if (!objectDescription.isEmpty()) {
                typeItem->setToolTip(objectDescription);
            }

            auto* valueItem = new QTableWidgetItem(snmpValueDisplayText(parsed.rawType, parsed.value));
            valueItem->setData(Qt::UserRole, parsed.rawType);
            valueItem->setData(Qt::UserRole + 1, snmpValueDisplayText(parsed.rawType, parsed.value));
            valueItem->setToolTip(parsed.value);

            m_snmpWidgets.table->setItem(row, 0, oidItem);
            m_snmpWidgets.table->setItem(row, 1, descItem);
            m_snmpWidgets.table->setItem(row, 2, typeItem);
            m_snmpWidgets.table->setItem(row, 3, valueItem);
            ++inserted;
        }
        m_snmpTablePopulating = false;

        if (inserted > 0) {
            m_snmpWidgets.table->selectRow(0);
            applySnmpTableFilter();
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#6fd27f;"));
                m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Доступных OID: %1", "Accessible OIDs: %1").arg(inserted));
            }
        } else if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "OID по этому запросу не найдены.", "No OIDs found for this query."));
        }
        process->deleteLater();
    });

    process->start(QStringLiteral("/usr/bin/snmpwalk"), args);
}

void MainWindow::applySnmpSelectedValue() {
    if (m_snmpWidgets.table == nullptr) {
        return;
    }
    const int row = m_snmpWidgets.table->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Сначала выберите строку OID.", "Select an OID row first."));
        return;
    }

    auto* oidItem = m_snmpWidgets.table->item(row, 0);
    auto* typeItem = m_snmpWidgets.table->item(row, 2);
    auto* valueItem = m_snmpWidgets.table->item(row, 3);
    if (oidItem == nullptr || typeItem == nullptr || valueItem == nullptr) {
        return;
    }

    const QString host = m_snmpWidgets.hostEdit->text().trimmed();
    const QString rawType = typeItem->data(Qt::UserRole).toString();
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    QString authError;
    const QString typeToken = snmpSetTypeToken(rawType);
    const QStringList authArgs = currentSnmpAuthArgs(true, &authError);
    if (authArgs.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), authError);
        return;
    }

    if (typeToken.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Этот тип OID нельзя изменить автоматически.", "This OID type cannot be changed automatically."));
        return;
    }

    const QString previousValue = valueItem->data(Qt::UserRole + 1).toString();
    const QString newValue = valueItem->text().trimmed();
    if (newValue.isEmpty() && typeToken != QStringLiteral("s")) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле значения пустое.", "Value field is empty."));
        m_snmpTablePopulating = true;
        valueItem->setText(previousValue);
        m_snmpTablePopulating = false;
        return;
    }

    if (m_snmpWidgets.loadButton != nullptr) {
        m_snmpWidgets.loadButton->setEnabled(false);
    }
    if (m_snmpWidgets.statusLabel != nullptr) {
        m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
        m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Изменение OID...", "Updating OID..."));
    }

    auto* process = new QProcess(this);
    QStringList args = authArgs;
    args << QStringLiteral("%1:%2").arg(host).arg(m_snmpWidgets.portSpin->value())
         << oidItem->text()
         << typeToken
         << newValue;

    connect(process, &QProcess::errorOccurred, this, [this, process, row, previousValue](QProcess::ProcessError) {
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
            m_snmpTablePopulating = true;
            valueItem->setText(previousValue);
            m_snmpTablePopulating = false;
        }
        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Не удалось запустить snmpset.", "Failed to start snmpset."));
        }
        process->deleteLater();
    });

    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this, process, row, previousValue](int exitCode, QProcess::ExitStatus exitStatus) {
        const QString stdOut = QString::fromUtf8(process->readAllStandardOutput());
        const QString stdErr = QString::fromUtf8(process->readAllStandardError()).trimmed();
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }

        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
                m_snmpTablePopulating = true;
                valueItem->setText(previousValue);
                m_snmpTablePopulating = false;
            }
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
                m_snmpWidgets.statusLabel->setText(stdErr.isEmpty()
                    ? uiText(m_settings, "Не удалось изменить значение OID.", "Failed to update OID value.")
                    : stdErr);
            }
            process->deleteLater();
            return;
        }

        const QStringList lines = stdOut.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
        for (const QString& line : lines) {
            const auto parsed = parseSnmpLine(line);
            if (!parsed.valid) {
                continue;
            }
            m_snmpTablePopulating = true;
            if (auto* typeItem = m_snmpWidgets.table->item(row, 2)) {
                typeItem->setText(snmpTypeDisplayText(parsed.rawType));
                typeItem->setData(Qt::UserRole, parsed.rawType);
            }
            if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
                valueItem->setText(snmpValueDisplayText(parsed.rawType, parsed.value));
                valueItem->setData(Qt::UserRole, parsed.rawType);
                valueItem->setData(Qt::UserRole + 1, snmpValueDisplayText(parsed.rawType, parsed.value));
                valueItem->setToolTip(parsed.value);
            }
            m_snmpTablePopulating = false;
            break;
        }

        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#6fd27f;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Значение OID обновлено.", "OID value updated."));
        }
        process->deleteLater();
    });

    process->start(QStringLiteral("/usr/bin/snmpset"), args);
}

void MainWindow::handleSnmpValueEdited(QTableWidgetItem* item) {
    if (m_snmpTablePopulating || item == nullptr || item->column() != 3) {
        return;
    }
    const QString previousValue = item->data(Qt::UserRole + 1).toString();
    const QString currentValue = item->text().trimmed();
    if (previousValue == currentValue) {
        return;
    }
    if (m_snmpWidgets.table != nullptr) {
        m_snmpWidgets.table->setCurrentItem(item);
    }
    applySnmpSelectedValue();
}

void MainWindow::loadSessionProfiles(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    widgets.profiles->clear();
    const auto profiles = m_settings->sessionProfiles(kind, defaultPort);
    for (const auto& profile : profiles) {
        const QString subtitle = profile.username.trimmed().isEmpty()
            ? QStringLiteral("%1:%2").arg(profile.host).arg(profile.port)
            : QStringLiteral("%1@%2:%3").arg(profile.username, profile.host).arg(profile.port);
        auto* item = new QListWidgetItem(QStringLiteral("%1\n%2").arg(profile.name, subtitle));
        item->setData(Qt::UserRole, QVariant::fromValue(profile));
        widgets.profiles->addItem(item);
    }
    if (widgets.profiles->count() > 0) {
        widgets.profiles->setCurrentRow(0);
    } else {
        newSessionProfile(widgets, defaultPort);
    }
}

void MainWindow::applySessionProfile(const nt::SessionProfile& profile, SessionWidgets& widgets) {
    widgets.nameEdit->setText(profile.name);
    widgets.hostEdit->setText(profile.host);
    widgets.portSpin->setValue(profile.port);
    widgets.userEdit->setText(profile.username);
    widgets.passEdit->setText(profile.password);
}

nt::SessionProfile MainWindow::currentSessionProfile(const SessionWidgets& widgets, quint16 defaultPort) const {
    nt::SessionProfile profile;
    profile.name = widgets.nameEdit->text().trimmed();
    profile.host = widgets.hostEdit->text().trimmed();
    profile.port = static_cast<quint16>(widgets.portSpin->value());
    profile.username = widgets.userEdit->text().trimmed();
    profile.password = widgets.passEdit->text();
    if (profile.port == 0) {
        profile.port = defaultPort;
    }
    if (profile.name.isEmpty()) {
        profile.name = QStringLiteral("%1:%2").arg(profile.host, QString::number(profile.port));
    }
    return profile;
}

void MainWindow::saveSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto profile = currentSessionProfile(widgets, defaultPort);
    if (profile.host.isEmpty()) {
        QMessageBox::warning(this, kind.toUpper(), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }

    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& item) {
        return item.name == profile.name;
    }), profiles.end());
    profiles.prepend(profile);
    while (profiles.size() > 80) {
        profiles.removeLast();
    }

    m_settings->storeSessionProfiles(kind, profiles, profile);
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::deleteSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto* item = widgets.profiles->currentItem();
    if (item == nullptr) {
        return;
    }
    const auto current = item->data(Qt::UserRole).value<nt::SessionProfile>();
    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return profile.name == current.name;
    }), profiles.end());
    m_settings->storeSessionProfiles(kind, profiles, currentSessionProfile(widgets, defaultPort));
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::newSessionProfile(SessionWidgets& widgets, quint16 defaultPort) {
    widgets.nameEdit->clear();
    widgets.hostEdit->setText(QStringLiteral("127.0.0.1"));
    widgets.portSpin->setValue(defaultPort);
    widgets.userEdit->clear();
    widgets.passEdit->clear();
}
