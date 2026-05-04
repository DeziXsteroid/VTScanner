#include "network/NetworkScanService.h"

#include "core/AppPaths.h"
#include "core/VendorDbService.h"

#include <QDateTime>
#include <QFileInfo>
#include <QHash>
#include <QHostAddress>
#include <QHostInfo>
#include <QSet>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QPointer>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QUdpSocket>
#include <QtConcurrent>

#include <algorithm>
#include <array>

#ifdef Q_OS_WIN
#include <QTcpSocket>
#else
#include <arpa/inet.h>
#include <cstdio>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace nt {

namespace {

bool isUsableIpv4(const QHostAddress& address) {
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    const QString ip = address.toString();
    return !ip.startsWith(QStringLiteral("127."))
        && !ip.startsWith(QStringLiteral("169.254."))
        && !ip.startsWith(QStringLiteral("198.18."));
}

int adapterScore(const AdapterInfo& adapter) {
    int score = 0;
    if (adapter.ip.startsWith(QStringLiteral("192.168."))) score += 50;
    else if (adapter.ip.startsWith(QStringLiteral("10."))) score += 45;
    else if (adapter.ip.startsWith(QStringLiteral("172."))) score += 35;
    if (adapter.prefixLength == 24) score += 12;
    else if (adapter.prefixLength >= 22 && adapter.prefixLength <= 26) score += 8;
    if (!adapter.isVpn) score += 20;
    return score;
}

QString shellQuote(const QString& value) {
    QString escaped = value;
    escaped.replace(QLatin1Char('\''), QStringLiteral("'\\''"));
    return QStringLiteral("'") + escaped + QStringLiteral("'");
}

QString systemCommandPath(const QString& program) {
#ifdef Q_OS_MACOS
    if (program == QStringLiteral("ping")) return QStringLiteral("/sbin/ping");
    if (program == QStringLiteral("arp")) return QStringLiteral("/usr/sbin/arp");
    if (program == QStringLiteral("netstat")) return QStringLiteral("/usr/sbin/netstat");
    if (program == QStringLiteral("dns-sd")) return QStringLiteral("/usr/bin/dns-sd");
    if (program == QStringLiteral("dscacheutil")) return QStringLiteral("/usr/bin/dscacheutil");
    if (program == QStringLiteral("ssh")) return QStringLiteral("/usr/bin/ssh");
    if (program == QStringLiteral("fping")) {
        const QString bundled = AppPaths::bundledToolPath(QStringLiteral("fping"));
        if (QFileInfo::exists(bundled)) return bundled;
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
        const QString discovered = QStandardPaths::findExecutable(QStringLiteral("fping"));
        if (!discovered.isEmpty()) return discovered;
    }
#elif defined(Q_OS_LINUX)
    if (program == QStringLiteral("ping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/ping"))) return QStringLiteral("/usr/bin/ping");
        if (QFileInfo::exists(QStringLiteral("/bin/ping"))) return QStringLiteral("/bin/ping");
    }
    if (program == QStringLiteral("fping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/fping"))) return QStringLiteral("/usr/sbin/fping");
        const QString discovered = QStandardPaths::findExecutable(QStringLiteral("fping"));
        if (!discovered.isEmpty()) return discovered;
    }
    if (program == QStringLiteral("ip")) {
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/ip"))) return QStringLiteral("/usr/sbin/ip");
        if (QFileInfo::exists(QStringLiteral("/sbin/ip"))) return QStringLiteral("/sbin/ip");
        if (QFileInfo::exists(QStringLiteral("/usr/bin/ip"))) return QStringLiteral("/usr/bin/ip");
    }
    if (program == QStringLiteral("arp")) {
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/arp"))) return QStringLiteral("/usr/sbin/arp");
        if (QFileInfo::exists(QStringLiteral("/sbin/arp"))) return QStringLiteral("/sbin/arp");
    }
#endif
    return program;
}

QString runCommandCapture(const QString& program, const QStringList& args, bool mergeStdErr = false, int* exitStatus = nullptr) {
#ifdef Q_OS_WIN
    QProcess process;
    process.setProcessChannelMode(mergeStdErr ? QProcess::MergedChannels : QProcess::SeparateChannels);
    process.start(systemCommandPath(program), args);
    if (!process.waitForFinished(2500)) {
        process.kill();
        process.waitForFinished(200);
        if (exitStatus != nullptr) {
            *exitStatus = -1;
        }
        return {};
    }
    if (exitStatus != nullptr) {
        *exitStatus = process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
    }
    return QString::fromLocal8Bit(process.readAllStandardOutput());
#else
    QStringList quoted;
    quoted.reserve(args.size() + 1);
    quoted.append(shellQuote(systemCommandPath(program)));
    for (const auto& arg : args) {
        quoted.append(shellQuote(arg));
    }
    QString command = quoted.join(QLatin1Char(' '));
    command += mergeStdErr ? QStringLiteral(" 2>&1") : QStringLiteral(" 2>/dev/null");

    FILE* pipe = ::popen(command.toUtf8().constData(), "r");
    if (pipe == nullptr) {
        if (exitStatus != nullptr) {
            *exitStatus = -1;
        }
        return {};
    }

    std::array<char, 512> buffer {};
    QByteArray output;
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output.append(buffer.data());
    }

    const int status = ::pclose(pipe);
    if (exitStatus != nullptr) {
        if (status == -1) {
            *exitStatus = -1;
        } else if (WIFEXITED(status)) {
            *exitStatus = WEXITSTATUS(status);
        } else {
            *exitStatus = -1;
        }
    }
    return QString::fromLocal8Bit(output);
#endif
}

QString runTimedCommandCapture(const QString& program, const QStringList& args, int timeoutMs, bool mergeStdErr);

QString executableCommandPath(const QString& program) {
    const QString systemPath = systemCommandPath(program);
    if (systemPath != program && QFileInfo::exists(systemPath)) {
        return systemPath;
    }

    const QString discovered = QStandardPaths::findExecutable(program);
    if (!discovered.isEmpty()) {
        return discovered;
    }

    return QFileInfo::exists(systemPath) ? systemPath : QString();
}

QString normalizeMacString(QString value) {
    value = value.trimmed().toLower();
    value.replace(QLatin1Char('-'), QLatin1Char(':'));
    if (value.contains(QLatin1Char('.'))) {
        QString hex = value;
        hex.remove(QLatin1Char('.'));
        if (hex.size() != 12) {
            return QStringLiteral("-");
        }
        QStringList parts;
        for (int index = 0; index < hex.size(); index += 2) {
            parts.append(hex.mid(index, 2));
        }
        return parts.join(QLatin1Char(':'));
    }

    const QStringList rawParts = value.split(QLatin1Char(':'), Qt::SkipEmptyParts);
    if (rawParts.size() == 6) {
        QStringList parts;
        parts.reserve(6);
        for (QString part : rawParts) {
            if (part.size() > 2) {
                return QStringLiteral("-");
            }
            parts.append(part.rightJustified(2, QLatin1Char('0')));
        }
        return parts.join(QLatin1Char(':'));
    }

    QString hex = value;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9a-f]")));
    if (hex.size() != 12) {
        return QStringLiteral("-");
    }
    QStringList parts;
    for (int index = 0; index < hex.size(); index += 2) {
        parts.append(hex.mid(index, 2));
    }
    return parts.join(QLatin1Char(':'));
}

QString normalizeResolvedName(QString value, const QString& ip) {
    value = value.trimmed();
    while (value.endsWith(QLatin1Char('.'))) {
        value.chop(1);
    }
    if (value.isEmpty()
        || value == QStringLiteral("?")
        || value.compare(ip, Qt::CaseInsensitive) == 0) {
        return {};
    }
    const QHostAddress asAddress(value);
    if (asAddress.protocol() == QAbstractSocket::IPv4Protocol
        && (ip.isEmpty() || asAddress.toString() == ip)) {
        return {};
    }
    return value;
}

bool isUnknownVendorLabel(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized == QStringLiteral("?")
        || normalized == QStringLiteral("unknown vendor");
}

bool isMissingPingDisplay(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized == QStringLiteral("?");
}

void mergeHelpfulScanFields(ScanRecord& target, const ScanRecord& source) {
    if (target.ip.isEmpty() || source.ip.isEmpty() || target.ip != source.ip) {
        return;
    }

    if ((target.mac.trimmed().isEmpty() || target.mac == QStringLiteral("-"))
        && !source.mac.trimmed().isEmpty()
        && source.mac != QStringLiteral("-")) {
        target.mac = source.mac;
    }

    if (isMissingPingDisplay(target.pingDisplay) && !isMissingPingDisplay(source.pingDisplay)) {
        target.pingDisplay = source.pingDisplay;
        if (source.status == HostStatus::Online) {
            target.status = HostStatus::Online;
        }
        if (isUnknownVendorLabel(target.speed) && !isUnknownVendorLabel(source.speed)) {
            target.speed = source.speed;
        }
        if (isUnknownVendorLabel(target.typeHint) && !isUnknownVendorLabel(source.typeHint)) {
            target.typeHint = source.typeHint;
        }
    } else if (target.status != HostStatus::Online && source.status == HostStatus::Online) {
        target.status = HostStatus::Online;
    }

    if (isUnknownVendorLabel(target.portsDisplay) && !isUnknownVendorLabel(source.portsDisplay)) {
        target.portsDisplay = source.portsDisplay;
    }
    if (isUnknownVendorLabel(target.port) && !isUnknownVendorLabel(source.port)) {
        target.port = source.port;
    }
    if (isUnknownVendorLabel(target.webDetect) && !isUnknownVendorLabel(source.webDetect)) {
        target.webDetect = source.webDetect;
    }
    if (isUnknownVendorLabel(target.typeHint) && !isUnknownVendorLabel(source.typeHint)) {
        target.typeHint = source.typeHint;
    }

    if (isUnknownVendorLabel(target.hostName) && !isUnknownVendorLabel(source.hostName)) {
        target.hostName = source.hostName;
    }
    if (!isUnknownVendorLabel(target.hostName)) {
        target.vendor = target.hostName;
    } else if (isUnknownVendorLabel(target.vendor) && !isUnknownVendorLabel(source.vendor)) {
        target.vendor = source.vendor;
    }

    if (isUnknownVendorLabel(target.name) && !isUnknownVendorLabel(source.name)) {
        target.name = source.name;
    }

    if ((target.gateway.trimmed().isEmpty() || target.gateway == QStringLiteral("-"))
        && !source.gateway.trimmed().isEmpty()
        && source.gateway != QStringLiteral("-")) {
        target.gateway = source.gateway;
    }
    if ((target.mask.trimmed().isEmpty() || target.mask == QStringLiteral("-"))
        && !source.mask.trimmed().isEmpty()
        && source.mask != QStringLiteral("-")) {
        target.mask = source.mask;
    }
}

bool hasUsefulSeedSignal(const ScanRecord& record) {
    return record.status == HostStatus::Online
        || !isMissingPingDisplay(record.pingDisplay)
        || !isUnknownVendorLabel(record.hostName)
        || !isUnknownVendorLabel(record.vendor);
}

int quickPingTimeoutForProfile(const QString& profile) {
    const QString normalized = profile.trimmed().toLower();
    if (normalized == QStringLiteral("fast")) {
        return 220;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 420;
    }
    return 300;
}

int quickPortTimeoutForProfile(const QString& profile) {
    const QString normalized = profile.trimmed().toLower();
    if (normalized == QStringLiteral("fast")) {
        return 130;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 280;
    }
    return 190;
}

int instantProbeLimitForProfile(const QString& profile) {
    const QString normalized = profile.trimmed().toLower();
    if (normalized == QStringLiteral("fast")) {
        return 28;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 12;
    }
    return 20;
}

struct CachedResolvedName {
    QString name;
    QString mac;
};

struct BonjourResolution {
    QHash<QString, QString> namesByIp;
    QHash<QString, QString> namesByMac;
};

struct ScanTiming {
    int pingTimeoutMs {650};
    int retryWindowMs {3200};
    int retryIntervalMs {240};
    int portTimeoutMs {260};
    int sweepTimeoutMs {300};
    int sweepIntervalMs {2};
};

struct ArpWarmupConfig {
    int maxIps {1024};
    int batchSize {96};
    int pauseMs {1};
};

QString normalizedScanProfile(QString profile) {
    profile = profile.trimmed().toLower();
    if (profile == QStringLiteral("fast") || profile == QStringLiteral("reliable")) {
        return profile;
    }
    return QStringLiteral("balanced");
}

ScanTiming scanTimingForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return ScanTiming{350, 1800, 180, 220, 180, 1};
    }
    if (normalized == QStringLiteral("reliable")) {
        return ScanTiming{1200, 5200, 300, 560, 500, 5};
    }
    return ScanTiming{650, 3200, 240, 360, 300, 2};
}

QList<quint16> probePortsForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return {22, 23, 80, 443, 554, 8080};
    }
    if (normalized == QStringLiteral("reliable")) {
        return {22, 23, 80, 443, 554, 3389, 8080, 8443, 9100};
    }
    return {22, 23, 80, 443, 554, 3389, 8080, 8443, 9100};
}

int workerCountForProfile(int requestedWorkers, const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return qBound(8, requestedWorkers, 128);
    }
    if (normalized == QStringLiteral("reliable")) {
        return qBound(2, requestedWorkers, 48);
    }
    return qBound(4, requestedWorkers, 96);
}

ArpWarmupConfig arpWarmupForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return ArpWarmupConfig{512, 128, 0};
    }
    if (normalized == QStringLiteral("reliable")) {
        return ArpWarmupConfig{2048, 32, 3};
    }
    return {};
}

int sweepChunkSizeForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return 512;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 128;
    }
    return 256;
}

QMutex& resolvedNameCacheMutex() {
    static QMutex mutex;
    return mutex;
}

QHash<QString, CachedResolvedName>& resolvedNameByIpCache() {
    static QHash<QString, CachedResolvedName> cache;
    return cache;
}

QHash<QString, QString>& resolvedNameByMacCache() {
    static QHash<QString, QString> cache;
    return cache;
}

void rememberResolvedName(const QString& ip, const QString& mac, const QString& name) {
    const QString normalizedName = normalizeResolvedName(name, ip);
    if (normalizedName.isEmpty()) {
        return;
    }
    const QString normalizedMac = normalizeMacString(mac);
    QMutexLocker locker(&resolvedNameCacheMutex());
    if (!ip.trimmed().isEmpty()) {
        resolvedNameByIpCache().insert(ip.trimmed(), CachedResolvedName{normalizedName, normalizedMac});
    }
    if (!normalizedMac.isEmpty() && normalizedMac != QStringLiteral("-")) {
        resolvedNameByMacCache().insert(normalizedMac, normalizedName);
    }
}

QString cachedResolvedName(const QString& ip, const QString& mac) {
    const QString normalizedIp = ip.trimmed();
    const QString normalizedMac = normalizeMacString(mac);
    QString ipFallback;
    QMutexLocker locker(&resolvedNameCacheMutex());

    const auto byIp = resolvedNameByIpCache().constFind(normalizedIp);
    if (byIp != resolvedNameByIpCache().constEnd()) {
        const bool macCompatible = byIp->mac.isEmpty()
            || normalizedMac.isEmpty()
            || normalizedMac == QStringLiteral("-")
            || byIp->mac == normalizedMac;
        if (!isUnknownVendorLabel(byIp->name)) {
            if (macCompatible) {
                return byIp->name;
            }
            ipFallback = byIp->name;
        }
    }

    if (!normalizedMac.isEmpty() && normalizedMac != QStringLiteral("-")) {
        const auto byMac = resolvedNameByMacCache().constFind(normalizedMac);
        if (byMac != resolvedNameByMacCache().constEnd() && !isUnknownVendorLabel(*byMac)) {
            return *byMac;
        }
    }
    return ipFallback;
}

QString extractResolvedNameFromPingOutput(const QString& output, const QString& ip) {
#ifdef Q_OS_WIN
    static const QRegularExpression headerRe(
        QStringLiteral("^Pinging\\s+(.+?)\\s+\\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\]"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption
    );
    const auto match = headerRe.match(output);
    if (match.hasMatch() && match.captured(2) == ip) {
        return normalizeResolvedName(match.captured(1), ip);
    }
#else
    static const QRegularExpression headerRe(
        QStringLiteral("^PING\\s+([^\\s]+)\\s+\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption
    );
    const auto match = headerRe.match(output);
    if (match.hasMatch() && match.captured(2) == ip) {
        return normalizeResolvedName(match.captured(1), ip);
    }
#endif
    return {};
}

QString firstResolvedNameFromLines(const QString& output, const QString& ip) {
    const QStringList lines = output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString& rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty()
            || line.startsWith(QStringLiteral(";;"))
            || line.contains(QStringLiteral("NXDOMAIN"), Qt::CaseInsensitive)
            || line.contains(QStringLiteral("not found"), Qt::CaseInsensitive)
            || line.contains(QStringLiteral("can't find"), Qt::CaseInsensitive)) {
            continue;
        }
        const QString normalized = normalizeResolvedName(line.section(QLatin1Char('\t'), 0, 0), ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }
    return {};
}

QString parsePtrToolOutput(const QString& output, const QString& ip) {
    static const QRegularExpression pointerRe(
        QStringLiteral("(?:pointer|name\\s*=|Name:)\\s+([^\\s]+)"),
        QRegularExpression::CaseInsensitiveOption
    );
    const auto pointerMatch = pointerRe.match(output);
    if (pointerMatch.hasMatch()) {
        const QString normalized = normalizeResolvedName(pointerMatch.captured(1), ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }

    return {};
}

QString resolvePtrNameWithTool(const QString& ip) {
#ifdef Q_OS_LINUX
    const QString getent = executableCommandPath(QStringLiteral("getent"));
    if (!getent.isEmpty()) {
        const QString output = runTimedCommandCapture(getent, {QStringLiteral("hosts"), ip}, 800, true);
        static const QRegularExpression getentRe(QStringLiteral("^\\s*\\S+\\s+([^\\s]+)"),
                                                 QRegularExpression::MultilineOption);
        const auto match = getentRe.match(output);
        if (match.hasMatch()) {
            const QString normalized = normalizeResolvedName(match.captured(1), ip);
            if (!normalized.isEmpty()) {
                return normalized;
            }
        }
    }
#endif

    const QString dig = executableCommandPath(QStringLiteral("dig"));
    if (!dig.isEmpty()) {
        const QString output = runTimedCommandCapture(dig, {QStringLiteral("+time=1"), QStringLiteral("+tries=1"), QStringLiteral("-x"), ip, QStringLiteral("+short")}, 900, true);
        const QString normalized = firstResolvedNameFromLines(output, ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }

    const QString host = executableCommandPath(QStringLiteral("host"));
    if (!host.isEmpty()) {
        const QString output = runTimedCommandCapture(host, {QStringLiteral("-W"), QStringLiteral("1"), ip}, 900, true);
        const QString normalized = parsePtrToolOutput(output, ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }

    const QString nslookup = executableCommandPath(QStringLiteral("nslookup"));
    if (!nslookup.isEmpty()) {
        const QString output = runTimedCommandCapture(nslookup, {ip}, 900, true);
        const QString normalized = parsePtrToolOutput(output, ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }

    return {};
}

QString reverseLookupName(const QString& ip) {
#ifdef Q_OS_MACOS
    const QString output = runTimedCommandCapture(
        QStringLiteral("dscacheutil"),
        {QStringLiteral("-q"), QStringLiteral("host"), QStringLiteral("-a"), QStringLiteral("ip_address"), ip},
        900,
        true
    );
    static const QRegularExpression nameRe(QStringLiteral("^name:\\s+(.+)$"), QRegularExpression::MultilineOption);
    const auto match = nameRe.match(output);
    if (match.hasMatch()) {
        const QString normalized = normalizeResolvedName(match.captured(1), ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }
#endif
    const QString toolName = resolvePtrNameWithTool(ip);
    if (!toolName.isEmpty()) {
        return toolName;
    }

    const auto hostInfo = QHostInfo::fromName(ip);
    if (hostInfo.error() == QHostInfo::NoError) {
        const QString normalized = normalizeResolvedName(hostInfo.hostName(), ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }
    return {};
}

QString routeDisplayForHost(const AdapterInfo& adapter, const ScanRecord& row) {
    if (row.onLink) {
        return adapter.id.isEmpty()
            ? QStringLiteral("напрямую")
            : QStringLiteral("напрямую (%1)").arg(adapter.id);
    }
    if (!row.gateway.trimmed().isEmpty() && row.gateway != QStringLiteral("-")) {
        return QStringLiteral("через %1").arg(row.gateway);
    }
    return QStringLiteral("-");
}

QList<QString> prioritizeIpsForScan(const QList<QString>& ips, const QHash<QString, QString>& knownMacs, const QString& gateway, const QString& localIp) {
    if (ips.isEmpty()) {
        return ips;
    }

    QList<QString> prioritized;
    prioritized.reserve(ips.size());
    QSet<QString> appended;
    const QSet<QString> ipSet(ips.constBegin(), ips.constEnd());

    const auto tryAppend = [&](const QString& ip) {
        if (!ip.isEmpty() && !appended.contains(ip) && ipSet.contains(ip)) {
            prioritized.append(ip);
            appended.insert(ip);
        }
    };

    tryAppend(gateway);
    tryAppend(localIp);

    QList<QString> knownIps;
    knownIps.reserve(knownMacs.size());
    for (auto it = knownMacs.constBegin(); it != knownMacs.constEnd(); ++it) {
        if (ipSet.contains(it.key())) {
            knownIps.append(it.key());
        }
    }
    std::sort(knownIps.begin(), knownIps.end(), [](const QString& left, const QString& right) {
        return QHostAddress(left).toIPv4Address() < QHostAddress(right).toIPv4Address();
    });
    for (const auto& ip : knownIps) {
        tryAppend(ip);
    }

    for (const auto& ip : ips) {
        tryAppend(ip);
    }
    return prioritized;
}

bool tryConnectPort(const QString& ip, quint16 port, int timeoutMs) {
#ifdef Q_OS_WIN
    QTcpSocket socket;
    socket.connectToHost(ip, port);
    if (!socket.waitForConnected(timeoutMs)) {
        return false;
    }
    socket.disconnectFromHost();
    socket.waitForDisconnected(50);
    return true;
#else
    const QByteArray ipBytes = ip.toUtf8();
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    sockaddr_in addr {};
#ifdef __APPLE__
    addr.sin_len = sizeof(addr);
#endif
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ipBytes.constData(), &addr.sin_addr) != 1) {
        ::close(fd);
        return false;
    }

    int result = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (result == 0) {
        ::close(fd);
        return true;
    }
    if (errno != EINPROGRESS) {
        ::close(fd);
        return false;
    }

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(fd, &writeSet);
    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    result = ::select(fd + 1, nullptr, &writeSet, nullptr, &timeout);
    if (result <= 0) {
        ::close(fd);
        return false;
    }

    int socketError = 0;
    socklen_t errorLength = sizeof(socketError);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) != 0) {
        ::close(fd);
        return false;
    }

    ::close(fd);
    return socketError == 0;
#endif
}

QString formatPingDisplay(const QString& value) {
    bool ok = false;
    QString normalized = value.trimmed();
    normalized.replace(QLatin1Char(','), QLatin1Char('.'));
    const double pingMs = normalized.toDouble(&ok);
    if (!ok) {
        return {};
    }
    return QStringLiteral("%1 ms").arg(qMax(1, qRound(pingMs)));
}

QString detectTypeHint(const QStringList& openPorts, bool pingSuccess, bool onLink) {
    const auto hasPort = [&](const QString& expected) {
        return std::any_of(openPorts.begin(), openPorts.end(), [&](const QString& value) {
            return value.trimmed().compare(expected, Qt::CaseInsensitive) == 0;
        });
    };

    if (hasPort(QStringLiteral("9100"))) {
        return QStringLiteral("printer");
    }
    if (hasPort(QStringLiteral("554"))) {
        return QStringLiteral("rtsp");
    }
    if (hasPort(QStringLiteral("443")) || hasPort(QStringLiteral("8443")) || hasPort(QStringLiteral("80")) || hasPort(QStringLiteral("8080"))) {
        return QStringLiteral("web");
    }
    if (hasPort(QStringLiteral("3389"))) {
        return QStringLiteral("rdp");
    }
    if (hasPort(QStringLiteral("22"))) {
        return QStringLiteral("ssh");
    }
    if (hasPort(QStringLiteral("23"))) {
        return QStringLiteral("telnet");
    }
    if (!openPorts.isEmpty()) {
        return QStringLiteral("tcp");
    }
    if (pingSuccess) {
        return QStringLiteral("icmp");
    }
    if (onLink) {
        return QStringLiteral("udp");
    }
    return QStringLiteral("-");
}

bool containsValueInsensitive(const QStringList& values, const QString& expected) {
    return std::any_of(values.begin(), values.end(), [&](const QString& value) {
        return value.trimmed().compare(expected, Qt::CaseInsensitive) == 0;
    });
}

QString mergePortDisplay(QString current, const QString& port) {
    QStringList parts = current.split(QLatin1Char(','), Qt::SkipEmptyParts);
    QStringList normalized;
    normalized.reserve(parts.size() + 1);
    for (QString part : parts) {
        part = part.trimmed();
        if (part.isEmpty()
            || part == QStringLiteral("-")
            || part == QStringLiteral("[n/a]")
            || containsValueInsensitive(normalized, part)) {
            continue;
        }
        normalized.append(part);
    }
    if (!port.trimmed().isEmpty() && !containsValueInsensitive(normalized, port)) {
        normalized.append(port.trimmed());
    }
    return normalized.isEmpty() ? QStringLiteral("-") : normalized.join(QLatin1Char(','));
}

QString vendorDisplayText(const QString& preferredName, const QString& mac, const VendorDbService* vendorDb) {
    QString normalizedName = normalizeResolvedName(preferredName, QString());
    if (isUnknownVendorLabel(normalizedName)) {
        normalizedName.clear();
    }
    if (!normalizedName.isEmpty()) {
        return normalizedName;
    }
    if (vendorDb == nullptr) {
        return QStringLiteral("unknown vendor");
    }
    const QString vendor = vendorDb->lookupVendor(mac).trimmed();
    return vendor.isEmpty() ? QStringLiteral("unknown vendor") : vendor;
}

QString runTimedCommandCapture(const QString& program, const QStringList& args, int timeoutMs, bool mergeStdErr = true) {
    QProcess process;
    process.setProcessChannelMode(mergeStdErr ? QProcess::MergedChannels : QProcess::SeparateChannels);
    process.start(systemCommandPath(program), args);
    if (!process.waitForStarted(qMin(timeoutMs, 1000))) {
        return {};
    }
    if (!process.waitForFinished(timeoutMs)) {
        process.terminate();
        if (!process.waitForFinished(250)) {
            process.kill();
            process.waitForFinished(250);
        }
    }
    return QString::fromUtf8(process.readAllStandardOutput());
}

QStringList parseDnsSdBrowseInstances(const QString& output, const QString& serviceType) {
    QStringList instances;
    const QRegularExpression lineRe(
        QStringLiteral("^\\S+\\s+Add\\s+\\S+\\s+\\d+\\s+\\S+\\s+%1\\.\\s+(.+)$")
            .arg(QRegularExpression::escape(serviceType)),
        QRegularExpression::MultilineOption
    );
    auto matchIt = lineRe.globalMatch(output);
    while (matchIt.hasNext()) {
        const QString instance = matchIt.next().captured(1).trimmed();
        if (!instance.isEmpty() && !instances.contains(instance)) {
            instances.append(instance);
        }
    }
    return instances;
}

QString parseDnsSdLookupTarget(const QString& output) {
    static const QRegularExpression targetRe(QStringLiteral("can be reached at\\s+(\\S+)\\.:\\d+"));
    const auto match = targetRe.match(output);
    if (!match.hasMatch()) {
        return {};
    }
    return match.captured(1).trimmed();
}

QString extractBonjourInstanceMac(const QString& instanceName) {
    const QString candidate = instanceName.section(QLatin1Char('@'), 0, 0).trimmed();
    const QString normalized = normalizeMacString(candidate);
    return normalized == QStringLiteral("-") ? QString() : normalized;
}

QStringList parseDnsSdResolvedIpv4(const QString& output) {
    QStringList ips;
    static const QRegularExpression ipRe(
        QStringLiteral("^\\S+\\s+Add\\s+\\S+\\s+\\d+\\s+\\S+\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+\\d+\\s*$"),
        QRegularExpression::MultilineOption
    );
    auto matchIt = ipRe.globalMatch(output);
    while (matchIt.hasNext()) {
        const QString ip = matchIt.next().captured(1).trimmed();
        if (!ip.isEmpty() && !ips.contains(ip)) {
            ips.append(ip);
        }
    }
    return ips;
}

QStringList resolveMdnsIpv4(const QString& hostName) {
    if (hostName.trimmed().isEmpty()) {
        return {};
    }
    const QString output = runTimedCommandCapture(
        QStringLiteral("dscacheutil"),
        {QStringLiteral("-q"), QStringLiteral("host"), QStringLiteral("-a"), QStringLiteral("name"), hostName},
        1600,
        true
    );
    QStringList ips;
    static const QRegularExpression ipRe(QStringLiteral("^ip_address:\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)$"), QRegularExpression::MultilineOption);
    auto matchIt = ipRe.globalMatch(output);
    while (matchIt.hasNext()) {
        const QString ip = matchIt.next().captured(1).trimmed();
        if (!ip.isEmpty() && !ips.contains(ip)) {
            ips.append(ip);
        }
    }
    if (!ips.isEmpty()) {
        return ips;
    }

#ifdef Q_OS_MACOS
    return parseDnsSdResolvedIpv4(runTimedCommandCapture(
        QStringLiteral("dns-sd"),
        {QStringLiteral("-G"), QStringLiteral("v4v6"), hostName},
        1200,
        true
    ));
#else
    return ips;
#endif
}

QString prettyBonjourName(const QString& serviceType, const QString& instanceName, const QString& targetHost) {
    QString hostBase = targetHost.trimmed();
    if (hostBase.endsWith(QStringLiteral(".local"), Qt::CaseInsensitive)) {
        hostBase.chop(QStringLiteral(".local").size());
    }

    QString display = hostBase;
    if (serviceType == QStringLiteral("_raop._tcp")) {
        const int atIndex = instanceName.indexOf(QLatin1Char('@'));
        if (atIndex >= 0 && atIndex + 1 < instanceName.size()) {
            display = instanceName.mid(atIndex + 1).trimmed();
        }
    } else if (serviceType == QStringLiteral("_airplay._tcp")
               || serviceType == QStringLiteral("_companion-link._tcp")
               || serviceType == QStringLiteral("_device-info._tcp")
               || serviceType == QStringLiteral("_hap._tcp")
               || serviceType == QStringLiteral("_sleep-proxy._udp")) {
        display = instanceName.trimmed();
    } else if (serviceType == QStringLiteral("_apple-mobdev2._tcp")) {
        if (display.isEmpty()) {
            display = instanceName.trimmed();
        }
    }

    display = display.trimmed();
    if (display.isEmpty()) {
        display = instanceName.trimmed();
    }
    if (display.contains(QStringLiteral("supportsRP-"), Qt::CaseInsensitive)) {
        display = hostBase;
    }
    return normalizeResolvedName(display, QString());
}

BonjourResolution collectBonjourNamesForService(const QSet<QString>& scannedIps, const QString& serviceType) {
    BonjourResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QString browseOutput = runTimedCommandCapture(
        QStringLiteral("dns-sd"),
        {QStringLiteral("-B"), serviceType, QStringLiteral("local")},
        1200,
        true
    );
    const QStringList instances = parseDnsSdBrowseInstances(browseOutput, serviceType);
    for (const auto& instance : instances) {
        const QString lookupOutput = runTimedCommandCapture(
            QStringLiteral("dns-sd"),
            {QStringLiteral("-L"), instance, serviceType, QStringLiteral("local")},
            1200,
            true
        );
        const QString targetHost = parseDnsSdLookupTarget(lookupOutput);
        const QString displayName = prettyBonjourName(serviceType, instance, targetHost);
        if (displayName.isEmpty()) {
            continue;
        }
        const QString instanceMac = extractBonjourInstanceMac(instance);
        if (!instanceMac.isEmpty() && !resolved.namesByMac.contains(instanceMac)) {
            resolved.namesByMac.insert(instanceMac, displayName);
        }

        const QStringList resolvedIps = resolveMdnsIpv4(targetHost);
        for (const auto& ip : resolvedIps) {
            if (!scannedIps.contains(ip) || resolved.namesByIp.contains(ip)) {
                continue;
            }
            resolved.namesByIp.insert(ip, displayName);
        }
    }
    return resolved;
}

BonjourResolution collectBonjourNames(const QSet<QString>& scannedIps) {
    BonjourResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QStringList serviceTypes {
        QStringLiteral("_workstation._tcp"),
        QStringLiteral("_http._tcp"),
        QStringLiteral("_https._tcp"),
        QStringLiteral("_ssh._tcp"),
        QStringLiteral("_smb._tcp"),
        QStringLiteral("_ipp._tcp"),
        QStringLiteral("_printer._tcp"),
        QStringLiteral("_scanner._tcp"),
        QStringLiteral("_rtsp._tcp"),
        QStringLiteral("_apple-mobdev2._tcp"),
        QStringLiteral("_airplay._tcp"),
        QStringLiteral("_raop._tcp"),
        QStringLiteral("_companion-link._tcp"),
        QStringLiteral("_device-info._tcp"),
        QStringLiteral("_hap._tcp"),
        QStringLiteral("_sleep-proxy._udp"),
    };

    QList<QFuture<BonjourResolution>> futures;
    futures.reserve(serviceTypes.size());
    for (const auto& serviceType : serviceTypes) {
        futures.append(QtConcurrent::run([scannedIps, serviceType]() {
            return collectBonjourNamesForService(scannedIps, serviceType);
        }));
    }

    for (auto& future : futures) {
        future.waitForFinished();
        const auto partial = future.result();
        for (auto it = partial.namesByIp.constBegin(); it != partial.namesByIp.constEnd(); ++it) {
            if (!resolved.namesByIp.contains(it.key())) {
                resolved.namesByIp.insert(it.key(), it.value());
            }
        }
        for (auto it = partial.namesByMac.constBegin(); it != partial.namesByMac.constEnd(); ++it) {
            if (!resolved.namesByMac.contains(it.key())) {
                resolved.namesByMac.insert(it.key(), it.value());
            }
        }
    }
    return resolved;
}

void warmArpCache(const QList<QString>& ips, const QString& scanProfile) {
    if (ips.isEmpty()) {
        return;
    }

    const ArpWarmupConfig config = arpWarmupForProfile(scanProfile);
    const QByteArray payload(1, '\0');
    QUdpSocket socket;

    for (int index = 0; index < ips.size() && index < config.maxIps; ++index) {
        const QHostAddress address(ips.at(index));
        if (address.protocol() != QAbstractSocket::IPv4Protocol) {
            continue;
        }
        socket.writeDatagram(payload, address, 9);
        if (config.pauseMs > 0 && (index + 1) % qMax(1, config.batchSize) == 0) {
            QThread::msleep(static_cast<unsigned long>(config.pauseMs));
        }
    }
}

} // namespace

NetworkScanService::NetworkScanService(VendorDbService* vendorDb, QObject* parent)
    : QObject(parent)
    , m_vendorDb(vendorDb)
    , m_watcher(new QFutureWatcher<nt::ScanRecord>(this)) {
    m_scanPool.setExpiryTimeout(30000);
    connect(m_watcher, &QFutureWatcher<nt::ScanRecord>::finished, this, [this]() {
        const auto future = m_watcher->future();
        if (m_cancelRequested.load()) {
            return;
        }
        QList<ScanRecord> records;
        const auto postScanMacs = captureArpTable(m_activeAdapter.id);
        if (!postScanMacs.isEmpty()) {
            mergePrefetchedMacs(postScanMacs);
        }
        const quint64 finishedGeneration = m_activeGeneration.load();
        records.reserve(future.resultCount());
        for (int index = 0; index < future.resultCount(); ++index) {
            auto record = future.resultAt(index);
            if (record.ip.isEmpty()) {
                continue;
            }
            if (record.mac.isEmpty() || record.mac == QStringLiteral("-")) {
                const QString refreshedMac = postScanMacs.value(record.ip, QStringLiteral("-"));
                if (!refreshedMac.isEmpty() && refreshedMac != QStringLiteral("-")) {
                    record.mac = refreshedMac;
                }
            }
            if (record.status == HostStatus::Offline
                && record.onLink
                && !record.mac.isEmpty()
                && record.mac != QStringLiteral("-")) {
                record.status = HostStatus::Unknown;
                record.typeHint = QStringLiteral("arp");
                record.speed = QStringLiteral("link");
                if (record.port.trimmed().isEmpty() || record.port == QStringLiteral("[n/a]")) {
                    record.port = QStringLiteral("-");
                }
                if (record.portsDisplay.trimmed().isEmpty() || record.portsDisplay == QStringLiteral("[n/a]")) {
                    record.portsDisplay = QStringLiteral("-");
                }
            }
            if (record.status != HostStatus::Offline) {
                const QString currentGateway = cachedGateway();
                if (record.gateway.trimmed().isEmpty()
                    || record.gateway == QStringLiteral("-")
                    || record.gateway == QStringLiteral("[n/a]")) {
                    record.gateway = currentGateway;
                }
                record.mask = record.mask.trimmed().isEmpty() ? m_cachedMask : record.mask;
                if (isUnknownVendorLabel(record.vendor)) {
                    const QString cachedName = cachedResolvedName(record.ip, record.mac);
                    if (!cachedName.isEmpty()) {
                        record.hostName = cachedName;
                        record.vendor = cachedName;
                    }
                }
                record.vendor = vendorDisplayText(
                    isUnknownVendorLabel(record.hostName) ? record.vendor : record.hostName,
                    record.mac,
                    m_vendorDb
                );
                {
                    QMutexLocker locker(&m_liveRecordsMutex);
                    const auto liveIt = m_liveRecords.constFind(record.ip);
                    if (liveIt != m_liveRecords.constEnd()) {
                        mergeHelpfulScanFields(record, liveIt.value());
                    }
                }
                record.name = routeDisplayForHost(m_activeAdapter, record);
                records.append(record);
            }
        }
        {
            QMutexLocker locker(&m_liveRecordsMutex);
            m_liveRecords.clear();
            for (const auto& record : records) {
                m_liveRecords.insert(record.ip, record);
            }
        }
        const int durationMs = static_cast<int>(QDateTime::currentMSecsSinceEpoch() - m_startedMs);
        const QString finishedProfile = m_activeScanProfile;
        emit scanFinished(records, durationMs);
        startNameEnrichment(records, finishedGeneration);
        startDetailEnrichment(records, finishedGeneration, finishedProfile);
        startRtspEnrichment(records, finishedGeneration);
    });
}

NetworkScanService::~NetworkScanService() {
    cancel();
    m_watcher->waitForFinished();
    m_scanPool.waitForDone();
}

QList<AdapterInfo> NetworkScanService::adapters() const {
    QList<AdapterInfo> items;
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const auto& iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp) || !(iface.flags() & QNetworkInterface::IsRunning)) {
            continue;
        }
        for (const auto& entry : iface.addressEntries()) {
            if (!isUsableIpv4(entry.ip())) {
                continue;
            }
            AdapterInfo item;
            item.id = iface.name();
            item.name = iface.humanReadableName().trimmed().isEmpty() ? iface.name() : iface.humanReadableName();
            item.ip = entry.ip().toString();
            item.prefixLength = entry.prefixLength();
            item.network = QHostAddress(entry.ip().toIPv4Address() & entry.netmask().toIPv4Address()).toString()
                + QStringLiteral("/") + QString::number(entry.prefixLength());
            item.isVpn = isVpnName(item.id) || isVpnName(item.name);
            items.append(item);
        }
    }
    return items;
}

RangeSuggestion NetworkScanService::suggestRange() const {
    RangeSuggestion suggestion;
    const auto list = adapters();
    if (list.isEmpty()) {
        suggestion.startIp = QStringLiteral("192.168.1.1");
        suggestion.endIp = QStringLiteral("192.168.1.254");
        suggestion.label = QStringLiteral("Резервный диапазон 192.168.1.0/24");
        return suggestion;
    }

    auto best = std::max_element(list.begin(), list.end(), [](const auto& left, const auto& right) {
        return adapterScore(left) < adapterScore(right);
    });
    const quint32 ip = QHostAddress(best->ip).toIPv4Address();
    const quint32 mask = best->prefixLength <= 0 ? 0xFFFFFF00u : (~0u << (32 - best->prefixLength));
    const quint32 network = ip & mask;
    const quint32 broadcast = network | (~mask);
    if (broadcast <= network + 1) {
        suggestion.startIp = intToIp(ip);
        suggestion.endIp = intToIp(ip);
    } else {
        suggestion.startIp = intToIp(network + 1);
        suggestion.endIp = intToIp(broadcast - 1);
    }
    suggestion.label = QStringLiteral("Автодиапазон от %1 / %2").arg(best->ip, best->network);
    suggestion.adapterId = best->id;
    return suggestion;
}

void NetworkScanService::start(const QString& startIp, const QString& endIp, const QString& adapterId, int maxWorkers, const QString& scanProfile, quint64 generation) {
    if (isRunning()) {
        return;
    }

    const auto ips = expandRange(startIp, endIp);
    if (ips.isEmpty()) {
        emit scanFailed(QStringLiteral("Неверный диапазон IP."));
        return;
    }

    m_cancelRequested.store(false);
    m_startedMs = QDateTime::currentMSecsSinceEpoch();
    m_activeGeneration.store(generation);
    {
        QMutexLocker locker(&m_liveRecordsMutex);
        m_liveRecords.clear();
    }
    m_activeAdapter = adapterById(adapterId);
    const auto adapter = m_activeAdapter;
    const QString activeScanProfile = normalizedScanProfile(scanProfile);
    m_activeScanProfile = activeScanProfile;
    m_scanPool.setMaxThreadCount(workerCountForProfile(maxWorkers, activeScanProfile));
    emit scanStarted();
    setCachedGateway(QStringLiteral("-"));
    m_cachedMask = detectMask(adapter);
    setPrefetchedMacs({});
    {
        QMutexLocker locker(&m_nameEnrichmentMutex);
        m_nameEnrichmentInFlight.clear();
    }
    {
        QMutexLocker locker(&m_prefetchedPingMutex);
        m_prefetchedPingDisplay.clear();
    }
    const auto initialKnownMacs = prefetchedMacsSnapshot();
    const auto scheduledIps = prioritizeIpsForScan(ips, initialKnownMacs, cachedGateway(), adapter.ip);
    const QSet<QString> scheduledIpSet(scheduledIps.constBegin(), scheduledIps.constEnd());

    QList<ScanRecord> seedRecords;
    seedRecords.reserve(qMin(initialKnownMacs.size(), scheduledIps.size()));
    for (auto it = initialKnownMacs.constBegin(); it != initialKnownMacs.constEnd(); ++it) {
        const QString ip = it.key().trimmed();
        const QString mac = it.value().trimmed();
        if (ip.isEmpty()
            || mac.isEmpty()
            || mac == QStringLiteral("-")
            || !scheduledIpSet.contains(ip)) {
            continue;
        }

        ScanRecord seed;
        seed.ip = ip;
        seed.generation = generation;
        seed.status = HostStatus::Unknown;
        seed.pingDisplay = QStringLiteral("[n/a]");
        seed.portsDisplay = QStringLiteral("-");
        seed.port = QStringLiteral("-");
        seed.webDetect = QStringLiteral("[n/a]");
        seed.speed = QStringLiteral("link");
        seed.mac = mac;
        seed.gateway = cachedGateway();
        seed.mask = m_cachedMask;
        seed.onLink = isOnLink(ip, adapter);
        seed.typeHint = QStringLiteral("arp");
        seed.hostName = cachedResolvedName(ip, mac);
        seed.vendor = vendorDisplayText(seed.hostName, seed.mac, m_vendorDb);
        seed.name = routeDisplayForHost(adapter, seed);
        seedRecords.append(seed);
    }
    std::sort(seedRecords.begin(), seedRecords.end(), [](const ScanRecord& left, const ScanRecord& right) {
        return QHostAddress(left.ip).toIPv4Address() < QHostAddress(right.ip).toIPv4Address();
    });

    QList<QString> immediateProbeIps;
    const int earlyProbeLimit = activeScanProfile == QStringLiteral("fast")
        ? 16
        : (activeScanProfile == QStringLiteral("reliable") ? 8 : 12);
    const int instantProbeLimit = instantProbeLimitForProfile(activeScanProfile);
    immediateProbeIps.reserve(earlyProbeLimit);
    for (const auto& ip : scheduledIps) {
        if (immediateProbeIps.size() >= earlyProbeLimit) {
            break;
        }
        const QString mac = initialKnownMacs.value(ip, QStringLiteral("-"));
        if (!mac.isEmpty() && mac != QStringLiteral("-")) {
            immediateProbeIps.append(ip);
        }
    }
    for (const auto& ip : scheduledIps) {
        if (immediateProbeIps.size() >= earlyProbeLimit) {
            break;
        }
        if (!immediateProbeIps.contains(ip)) {
            immediateProbeIps.append(ip);
        }
    }

    QList<QString> instantProbeIps;
    instantProbeIps.reserve(instantProbeLimit);
    for (const auto& ip : scheduledIps) {
        if (instantProbeIps.size() >= instantProbeLimit) {
            break;
        }
        const QString mac = initialKnownMacs.value(ip, QStringLiteral("-"));
        if (!mac.isEmpty() && mac != QStringLiteral("-")) {
            instantProbeIps.append(ip);
        }
    }
    for (const auto& ip : scheduledIps) {
        if (instantProbeIps.size() >= instantProbeLimit) {
            break;
        }
        if (!instantProbeIps.contains(ip)) {
            instantProbeIps.append(ip);
        }
    }

    (void)QtConcurrent::run([scheduledIps, adapter, activeScanProfile]() {
        QList<QString> onLinkIps;
        onLinkIps.reserve(scheduledIps.size());
        for (const auto& ip : scheduledIps) {
            if (isOnLink(ip, adapter) && ip != adapter.ip) {
                onLinkIps.append(ip);
            }
        }
        if (!onLinkIps.isEmpty()) {
            warmArpCache(onLinkIps, activeScanProfile);
        }
    });
#ifdef Q_OS_MACOS
    QTimer::singleShot(250, this, [this, scheduledIps, generation]() {
        if (!m_cancelRequested.load() && generation == m_activeGeneration.load()) {
            startBonjourEnrichment(scheduledIps, generation);
        }
    });
#endif

    const auto launchPrioritizedProbe = [this, adapter, generation, activeScanProfile](const QString& ip, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, activeScanProfile, ip]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run([this, adapter, generation, activeScanProfile, ip]() {
                if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                    return;
                }
                auto record = probeHost(ip, adapter, activeScanProfile);
                if (m_cancelRequested.load()
                    || record.ip.isEmpty()
                    || record.status == HostStatus::Offline
                    || record.generation != m_activeGeneration.load()) {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, record]() mutable {
                    if (m_cancelRequested.load() || record.generation != m_activeGeneration.load()) {
                        return;
                    }
                    {
                        QMutexLocker locker(&m_liveRecordsMutex);
                        const auto liveIt = m_liveRecords.constFind(record.ip);
                        if (liveIt != m_liveRecords.constEnd()) {
                            mergeHelpfulScanFields(record, liveIt.value());
                        }
                        m_liveRecords.insert(record.ip, record);
                    }
                    emit recordReady(record);
                }, Qt::QueuedConnection);
            });
        });
    };

    const auto launchFallbackSeed = [this, generation](ScanRecord seed, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, generation, seed]() mutable {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }
            const QString cachedName = cachedResolvedName(seed.ip, seed.mac);
            if (!cachedName.isEmpty()) {
                seed.hostName = cachedName;
                seed.vendor = cachedName;
            } else {
                seed.vendor = vendorDisplayText(seed.hostName, seed.mac, m_vendorDb);
            }
            {
                QMutexLocker locker(&m_prefetchedPingMutex);
                const auto pingIt = m_prefetchedPingDisplay.constFind(seed.ip);
                if (pingIt != m_prefetchedPingDisplay.constEnd() && !pingIt.value().trimmed().isEmpty()) {
                    seed.status = HostStatus::Online;
                    seed.pingDisplay = pingIt.value();
                    seed.speed = QStringLiteral("icmp");
                    seed.typeHint = QStringLiteral("icmp");
                }
            }
            if (!hasUsefulSeedSignal(seed)) {
                return;
            }
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }
            {
                QMutexLocker locker(&m_liveRecordsMutex);
                const auto liveIt = m_liveRecords.constFind(seed.ip);
                if (liveIt != m_liveRecords.constEnd()) {
                    const bool canImprovePing = isMissingPingDisplay(liveIt->pingDisplay)
                        && !isMissingPingDisplay(seed.pingDisplay);
                    const bool canImproveHostName = isUnknownVendorLabel(liveIt->hostName)
                        && !isUnknownVendorLabel(seed.hostName);
                    const bool canImproveVendor = isUnknownVendorLabel(liveIt->vendor)
                        && !isUnknownVendorLabel(seed.vendor);
                    if (!canImprovePing && !canImproveHostName && !canImproveVendor) {
                        return;
                    }
                    ScanRecord merged = liveIt.value();
                    mergeHelpfulScanFields(merged, seed);
                    m_liveRecords.insert(seed.ip, merged);
                    seed = merged;
                } else {
                    m_liveRecords.insert(seed.ip, seed);
                }
            }
            emit recordReady(seed);
        });
    };

    const auto launchPingSeed = [this, adapter, generation](const QString& ip, const QString& pingDisplay, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, ip, pingDisplay]() mutable {
            if (m_cancelRequested.load()
                || generation != m_activeGeneration.load()
                || ip.trimmed().isEmpty()
                || pingDisplay.trimmed().isEmpty()) {
                return;
            }

            ScanRecord record;
            record.ip = ip;
            record.generation = generation;
            record.status = HostStatus::Online;
            record.pingDisplay = pingDisplay;
            record.portsDisplay = QStringLiteral("-");
            record.port = QStringLiteral("-");
            record.webDetect = QStringLiteral("[n/a]");
            record.speed = QStringLiteral("icmp");
            record.typeHint = QStringLiteral("icmp");
            record.mac = prefetchedMacForIp(ip);
            record.gateway = cachedGateway();
            record.mask = m_cachedMask;
            record.onLink = isOnLink(ip, adapter);
            record.hostName = cachedResolvedName(ip, record.mac);
            record.vendor = vendorDisplayText(record.hostName, record.mac, m_vendorDb);
            record.name = routeDisplayForHost(adapter, record);

            bool shouldEmit = false;
            {
                QMutexLocker locker(&m_liveRecordsMutex);
                const auto liveIt = m_liveRecords.constFind(record.ip);
                if (liveIt != m_liveRecords.constEnd()) {
                    const bool canImprovePing = isMissingPingDisplay(liveIt->pingDisplay)
                        && !isMissingPingDisplay(record.pingDisplay);
                    const bool canImproveHostName = isUnknownVendorLabel(liveIt->hostName)
                        && !isUnknownVendorLabel(record.hostName);
                    const bool canImproveVendor = isUnknownVendorLabel(liveIt->vendor)
                        && !isUnknownVendorLabel(record.vendor);
                    if (!canImprovePing && !canImproveHostName && !canImproveVendor) {
                        return;
                    }
                    ScanRecord merged = liveIt.value();
                    mergeHelpfulScanFields(merged, record);
                    m_liveRecords.insert(record.ip, merged);
                    record = merged;
                    shouldEmit = true;
                } else {
                    m_liveRecords.insert(record.ip, record);
                    shouldEmit = true;
                }
            }
            if (shouldEmit) {
                emit recordReady(record);
            }
        });
    };

    const auto launchInstantProbe = [this, adapter, generation, activeScanProfile](const QString& ip, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, activeScanProfile, ip]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run([this, adapter, generation, activeScanProfile, ip]() {
                if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                    return;
                }

                ScanRecord record;
                record.ip = ip;
                record.generation = generation;
                record.status = HostStatus::Offline;
                record.pingDisplay = QStringLiteral("[n/a]");
                record.portsDisplay = QStringLiteral("-");
                record.port = QStringLiteral("-");
                record.webDetect = QStringLiteral("[n/a]");
                record.speed = QStringLiteral("[n/a]");
                record.typeHint = QStringLiteral("[n/a]");
                record.mac = prefetchedMacForIp(ip);
                record.gateway = cachedGateway();
                record.mask = m_cachedMask;
                record.onLink = isOnLink(ip, adapter);
                record.hostName = cachedResolvedName(ip, record.mac);
                record.vendor = vendorDisplayText(record.hostName, record.mac, m_vendorDb);
                record.name = routeDisplayForHost(adapter, record);

                PingResult ping;
                {
                    QMutexLocker locker(&m_prefetchedPingMutex);
                    const auto pingIt = m_prefetchedPingDisplay.constFind(ip);
                    if (pingIt != m_prefetchedPingDisplay.constEnd() && !pingIt.value().trimmed().isEmpty()) {
                        ping.success = true;
                        ping.display = pingIt.value();
                    }
                }
                if (!ping.success) {
                    ping = pingHost(ip, adapter.ip, quickPingTimeoutForProfile(activeScanProfile));
                    if (ping.success && !ping.display.trimmed().isEmpty()) {
                        QMutexLocker locker(&m_prefetchedPingMutex);
                        m_prefetchedPingDisplay.insert(ip, ping.display);
                    }
                }

                if (ping.success) {
                    record.status = HostStatus::Online;
                    record.pingDisplay = ping.display.isEmpty() ? QStringLiteral("online") : ping.display;
                    record.speed = QStringLiteral("icmp");
                    record.typeHint = QStringLiteral("icmp");
                    if (record.hostName.isEmpty()) {
                        record.hostName = ping.resolvedName;
                    }
                    if (!isUnknownVendorLabel(record.hostName)) {
                        record.vendor = record.hostName;
                    }
                } else if (record.onLink && !record.mac.isEmpty() && record.mac != QStringLiteral("-")) {
                    record.status = HostStatus::Unknown;
                    record.speed = QStringLiteral("link");
                    record.typeHint = QStringLiteral("arp");
                }

                const bool canShowInitial = record.status != HostStatus::Offline
                    && (ping.success || hasUsefulSeedSignal(record));
                if (canShowInitial) {
                    QMetaObject::invokeMethod(this, [this, record]() mutable {
                        publishLiveRecord(record);
                    }, Qt::QueuedConnection);
                }

                if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                    return;
                }

                QStringList openPorts = probeOpenPorts(ip, quickPortTimeoutForProfile(activeScanProfile), activeScanProfile);
                bool enriched = false;
                if (!openPorts.isEmpty()) {
                    record.status = ping.success ? HostStatus::Online : HostStatus::Unknown;
                    record.portsDisplay = openPorts.join(QLatin1Char(','));
                    record.port = record.portsDisplay;
                    record.webDetect = detectWebService(ip, openPorts);
                    record.typeHint = detectTypeHint(openPorts, ping.success, record.onLink);
                    record.speed = ping.success ? QStringLiteral("icmp") : QStringLiteral("tcp");
                    enriched = true;
                }

                if ((record.status != HostStatus::Offline)
                    && record.hostName.isEmpty()
                    && (ping.success || !openPorts.isEmpty())) {
                    const QString resolvedName = reverseLookupName(ip);
                    if (!resolvedName.isEmpty()) {
                        record.hostName = resolvedName;
                        record.vendor = resolvedName;
                        rememberResolvedName(record.ip, record.mac, resolvedName);
                        enriched = true;
                    }
                }

                if (!canShowInitial && record.status != HostStatus::Offline) {
                    enriched = true;
                }
                if (enriched && !m_cancelRequested.load() && generation == m_activeGeneration.load()) {
                    QMetaObject::invokeMethod(this, [this, record]() mutable {
                        publishLiveRecord(record);
                    }, Qt::QueuedConnection);
                }
            });
        });
    };

    for (int index = 0; index < instantProbeIps.size(); ++index) {
        launchInstantProbe(instantProbeIps.at(index), index * 22);
    }
    for (int index = 0; index < immediateProbeIps.size(); ++index) {
        launchPrioritizedProbe(immediateProbeIps.at(index), 140 + index * 65);
    }
    const int fallbackStartDelayMs = activeScanProfile == QStringLiteral("fast")
        ? 420
        : (activeScanProfile == QStringLiteral("reliable") ? 900 : 620);
    const int fallbackStepMs = activeScanProfile == QStringLiteral("fast")
        ? 70
        : (activeScanProfile == QStringLiteral("reliable") ? 130 : 95);
    for (int index = 0; index < seedRecords.size(); ++index) {
        const int delayMs = fallbackStartDelayMs + index * fallbackStepMs;
        launchFallbackSeed(seedRecords.at(index), delayMs);
    }

    (void)QtConcurrent::run([this, adapter, generation, scheduledIpSet, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
        const QString detectedGateway = detectGateway(adapter);
        const auto discoveredMacs = captureArpTable(adapter.id);
        if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
            return;
        }

        QMetaObject::invokeMethod(this, [this, adapter, generation, scheduledIpSet, detectedGateway, discoveredMacs, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            const QString gateway = detectedGateway.trimmed().isEmpty() ? QStringLiteral("-") : detectedGateway.trimmed();
            if (gateway != QStringLiteral("-")) {
                setCachedGateway(gateway);
            }
            if (!discoveredMacs.isEmpty()) {
                mergePrefetchedMacs(discoveredMacs);
            }

            QList<ScanRecord> updates;
            {
                QMutexLocker locker(&m_liveRecordsMutex);
                for (auto it = m_liveRecords.begin(); it != m_liveRecords.end(); ++it) {
                    ScanRecord updated = it.value();
                    bool changed = false;
                    if ((updated.gateway.trimmed().isEmpty() || updated.gateway == QStringLiteral("-"))
                        && !gateway.isEmpty()
                        && gateway != QStringLiteral("-")) {
                        updated.gateway = gateway;
                        changed = true;
                    }
                    if ((updated.mac.trimmed().isEmpty() || updated.mac == QStringLiteral("-"))) {
                        const QString mac = discoveredMacs.value(updated.ip, QStringLiteral("-"));
                        if (!mac.trimmed().isEmpty() && mac != QStringLiteral("-")) {
                            updated.mac = mac;
                            changed = true;
                        }
                    }
                    const QString cachedName = cachedResolvedName(updated.ip, updated.mac);
                    if (!cachedName.isEmpty() && isUnknownVendorLabel(updated.hostName)) {
                        updated.hostName = cachedName;
                        updated.vendor = cachedName;
                        changed = true;
                    } else if (isUnknownVendorLabel(updated.vendor)) {
                        const QString vendor = vendorDisplayText(updated.hostName, updated.mac, m_vendorDb);
                        if (!isUnknownVendorLabel(vendor)) {
                            updated.vendor = vendor;
                            changed = true;
                        }
                    }
                    const QString routeName = routeDisplayForHost(adapter, updated);
                    if (updated.name != routeName) {
                        updated.name = routeName;
                        changed = true;
                    }
                    if (changed) {
                        it.value() = updated;
                        updates.append(updated);
                    }
                }
            }
            for (const auto& update : updates) {
                emit recordReady(update);
            }

            QList<ScanRecord> discoveredSeeds;
            discoveredSeeds.reserve(qMin(discoveredMacs.size(), scheduledIpSet.size()));
            for (auto it = discoveredMacs.constBegin(); it != discoveredMacs.constEnd(); ++it) {
                if (!scheduledIpSet.contains(it.key())) {
                    continue;
                }
                ScanRecord seed;
                seed.ip = it.key();
                seed.generation = generation;
                seed.status = HostStatus::Unknown;
                seed.pingDisplay = QStringLiteral("[n/a]");
                seed.portsDisplay = QStringLiteral("-");
                seed.port = QStringLiteral("-");
                seed.webDetect = QStringLiteral("[n/a]");
                seed.speed = QStringLiteral("link");
                seed.mac = it.value();
                seed.gateway = gateway;
                seed.mask = m_cachedMask;
                seed.onLink = isOnLink(seed.ip, adapter);
                seed.typeHint = QStringLiteral("arp");
                seed.hostName = cachedResolvedName(seed.ip, seed.mac);
                seed.vendor = vendorDisplayText(seed.hostName, seed.mac, m_vendorDb);
                seed.name = routeDisplayForHost(adapter, seed);
                discoveredSeeds.append(seed);
            }
            std::sort(discoveredSeeds.begin(), discoveredSeeds.end(), [](const ScanRecord& left, const ScanRecord& right) {
                return QHostAddress(left.ip).toIPv4Address() < QHostAddress(right.ip).toIPv4Address();
            });

            const int probeLimit = qMin(discoveredSeeds.size(), instantProbeLimitForProfile(activeScanProfile));
            for (int index = 0; index < discoveredSeeds.size(); ++index) {
                launchFallbackSeed(discoveredSeeds.at(index), 20 + index * 50);
                if (index < probeLimit) {
                    launchInstantProbe(discoveredSeeds.at(index).ip, index * 18);
                }
            }
        }, Qt::QueuedConnection);
    });

    const QSet<QString> immediateProbeSet(immediateProbeIps.constBegin(), immediateProbeIps.constEnd());
    (void)QtConcurrent::run([this, adapter, generation, startIp, endIp, scheduledIps, immediateProbeSet, launchPrioritizedProbe, launchPingSeed, activeScanProfile, earlyProbeLimit]() {
        const auto prefetchedPing = sweepPingRange(startIp, endIp, adapter, activeScanProfile);
        if (prefetchedPing.isEmpty()) {
            return;
        }

        QMetaObject::invokeMethod(this, [this, adapter, generation, scheduledIps, immediateProbeSet, prefetchedPing, launchPrioritizedProbe, launchPingSeed, activeScanProfile, earlyProbeLimit]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            {
                QMutexLocker locker(&m_prefetchedPingMutex);
                for (auto it = prefetchedPing.constBegin(); it != prefetchedPing.constEnd(); ++it) {
                    m_prefetchedPingDisplay.insert(it.key(), it.value());
                }
            }

            int pingSeedIndex = 0;
            const int pingSeedStartMs = activeScanProfile == QStringLiteral("fast")
                ? 0
                : (activeScanProfile == QStringLiteral("reliable") ? 40 : 20);
            const int pingSeedStepMs = activeScanProfile == QStringLiteral("fast")
                ? 24
                : (activeScanProfile == QStringLiteral("reliable") ? 55 : 32);
            for (const auto& ip : scheduledIps) {
                const auto pingIt = prefetchedPing.constFind(ip);
                if (pingIt == prefetchedPing.constEnd()) {
                    continue;
                }
                launchPingSeed(ip, pingIt.value(), pingSeedStartMs + pingSeedIndex * pingSeedStepMs);
                ++pingSeedIndex;
            }

            int launchIndex = 0;
            for (const auto& ip : scheduledIps) {
                if (launchIndex >= earlyProbeLimit) {
                    break;
                }
                if (!prefetchedPing.contains(ip) || immediateProbeSet.contains(ip)) {
                    continue;
                }
                bool alreadyVisible = false;
                {
                    QMutexLocker locker(&m_liveRecordsMutex);
                    alreadyVisible = m_liveRecords.contains(ip);
                }
                if (alreadyVisible) {
                    continue;
                }
                launchPrioritizedProbe(ip, launchIndex * 32);
                ++launchIndex;
            }
        }, Qt::QueuedConnection);
    });

    auto future = QtConcurrent::mapped(&m_scanPool, scheduledIps, [this, adapter, activeScanProfile](const QString& ip) {
        if (m_cancelRequested.load()) {
            return ScanRecord{};
        }
        const int firstPaintWindowMs = activeScanProfile == QStringLiteral("fast") ? 90 : 160;
        const qint64 elapsedMs = QDateTime::currentMSecsSinceEpoch() - m_startedMs;
        if (elapsedMs >= 0 && elapsedMs < firstPaintWindowMs) {
            QThread::msleep(static_cast<unsigned long>(firstPaintWindowMs - elapsedMs));
        }
        auto record = probeHost(ip, adapter, activeScanProfile);
        if (!m_cancelRequested.load()
            && !record.ip.isEmpty()
            && record.status != HostStatus::Offline
            && record.generation == m_activeGeneration.load()) {
            QMetaObject::invokeMethod(this, [this, record]() mutable {
                if (!m_cancelRequested.load() && record.generation == m_activeGeneration.load()) {
                    {
                        QMutexLocker locker(&m_liveRecordsMutex);
                        const auto liveIt = m_liveRecords.constFind(record.ip);
                        if (liveIt != m_liveRecords.constEnd()) {
                            mergeHelpfulScanFields(record, liveIt.value());
                        }
                        m_liveRecords.insert(record.ip, record);
                    }
                    emit recordReady(record);
                }
            }, Qt::QueuedConnection);
        }
        return record;
    });
    m_watcher->setFuture(future);
}

void NetworkScanService::cancel() {
    m_cancelRequested.store(true);
    auto future = m_watcher->future();
    if (future.isRunning()) {
        future.cancel();
    }
    m_scanPool.clear();
    {
        QMutexLocker locker(&m_liveRecordsMutex);
        m_liveRecords.clear();
    }
    {
        QMutexLocker locker(&m_nameEnrichmentMutex);
        m_nameEnrichmentInFlight.clear();
    }
}

bool NetworkScanService::isRunning() const {
    return m_watcher->isRunning();
}

void NetworkScanService::startBonjourEnrichment(const QList<QString>& ips, quint64 generation) {
#ifndef Q_OS_MACOS
    Q_UNUSED(ips)
    Q_UNUSED(generation)
    return;
#else
    QSet<QString> scannedIps;
    for (const auto& ip : ips) {
        if (!ip.trimmed().isEmpty()) {
            scannedIps.insert(ip.trimmed());
        }
    }
    if (scannedIps.isEmpty()) {
        return;
    }

    QPointer<NetworkScanService> guard(this);
    (void)QtConcurrent::run([guard, generation, scannedIps]() {
        const auto bonjourNames = collectBonjourNames(scannedIps);
        if (!guard || (bonjourNames.namesByIp.isEmpty() && bonjourNames.namesByMac.isEmpty())) {
            return;
        }
        QMetaObject::invokeMethod(guard.data(), [guard, generation, bonjourNames]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }

            for (auto it = bonjourNames.namesByMac.constBegin(); it != bonjourNames.namesByMac.constEnd(); ++it) {
                rememberResolvedName(QString(), it.key(), it.value());
            }
            for (auto it = bonjourNames.namesByIp.constBegin(); it != bonjourNames.namesByIp.constEnd(); ++it) {
                rememberResolvedName(it.key(), QString(), it.value());
            }

            QHash<QString, QString> namesByRecordIp = bonjourNames.namesByIp;
            {
                QMutexLocker locker(&guard->m_liveRecordsMutex);
                for (auto liveIt = guard->m_liveRecords.constBegin(); liveIt != guard->m_liveRecords.constEnd(); ++liveIt) {
                    const QString normalizedMac = normalizeMacString(liveIt->mac);
                    if (normalizedMac.isEmpty() || normalizedMac == QStringLiteral("-")) {
                        continue;
                    }
                    const auto macIt = bonjourNames.namesByMac.constFind(normalizedMac);
                    if (macIt != bonjourNames.namesByMac.constEnd() && !namesByRecordIp.contains(liveIt.key())) {
                        namesByRecordIp.insert(liveIt.key(), macIt.value());
                    }
                }
            }

            for (auto it = namesByRecordIp.constBegin(); it != namesByRecordIp.constEnd(); ++it) {
                ScanRecord updated;
                bool shouldEmit = false;
                QString recordMac;
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(it.key());
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        updated = liveIt.value();
                        recordMac = updated.mac;
                        updated.hostName = it.value();
                        updated.vendor = it.value();
                        guard->m_liveRecords.insert(it.key(), updated);
                        shouldEmit = true;
                    }
                }
                if (!shouldEmit) {
                    continue;
                }
                rememberResolvedName(it.key(), recordMac, it.value());
                emit guard->recordReady(updated);
            }
        }, Qt::QueuedConnection);
    });
#endif
}

void NetworkScanService::startRtspEnrichment(const QList<ScanRecord>& records, quint64 generation) {
    QList<ScanRecord> candidates;
    candidates.reserve(records.size());

    for (const auto& record : records) {
        if (record.ip.trimmed().isEmpty() || record.status == HostStatus::Offline) {
            continue;
        }
        const QString rtspUrl = QStringLiteral("rtsp://%1:554").arg(record.ip);
        if (record.webDetect.contains(rtspUrl, Qt::CaseInsensitive)) {
            continue;
        }
        candidates.append(record);
    }

    if (candidates.isEmpty()) {
        return;
    }

    QPointer<NetworkScanService> guard(this);
    (void)QtConcurrent::run([guard, generation, candidates]() {
        QList<ScanRecord> updates;
        updates.reserve(candidates.size());

        for (const auto& record : candidates) {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }
            if (!tryConnectPort(record.ip, 554, 110)) {
                continue;
            }

            auto updated = record;
            updated.webDetect = QStringLiteral("rtsp://%1:554").arg(updated.ip);
            updated.portsDisplay = mergePortDisplay(updated.portsDisplay, QStringLiteral("554"));
            updated.port = mergePortDisplay(updated.port, QStringLiteral("554"));
            const QString normalizedType = updated.typeHint.trimmed().toLower();
            if (normalizedType.isEmpty()
                || normalizedType == QStringLiteral("-")
                || normalizedType == QStringLiteral("[n/a]")
                || normalizedType == QStringLiteral("tcp")
                || normalizedType == QStringLiteral("icmp")
                || normalizedType == QStringLiteral("udp")
                || normalizedType == QStringLiteral("link")
                || normalizedType == QStringLiteral("web")) {
                updated.typeHint = QStringLiteral("rtsp");
            }
            updates.append(updated);
        }

        if (!guard || updates.isEmpty()) {
            return;
        }

        QMetaObject::invokeMethod(guard.data(), [guard, generation, updates]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }
            for (auto updated : updates) {
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(updated.ip);
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        ScanRecord merged = liveIt.value();
                        merged.webDetect = updated.webDetect;
                        merged.portsDisplay = updated.portsDisplay;
                        merged.port = updated.port;
                        merged.typeHint = updated.typeHint;
                        guard->m_liveRecords.insert(updated.ip, merged);
                        updated = merged;
                    } else {
                        guard->m_liveRecords.insert(updated.ip, updated);
                    }
                }
                emit guard->recordReady(updated);
            }
        }, Qt::QueuedConnection);
    });
}

void NetworkScanService::startNameEnrichment(const QList<ScanRecord>& records, quint64 generation) {
    QList<ScanRecord> candidates;
    candidates.reserve(records.size());
    {
        QMutexLocker locker(&m_nameEnrichmentMutex);
        for (const auto& record : records) {
            if (record.ip.trimmed().isEmpty()
                || record.status == HostStatus::Offline
                || !isUnknownVendorLabel(record.hostName)
                || m_nameEnrichmentInFlight.contains(record.ip)) {
                continue;
            }
            m_nameEnrichmentInFlight.insert(record.ip);
            candidates.append(record);
        }
    }
    if (candidates.isEmpty()) {
        return;
    }

    QPointer<NetworkScanService> guard(this);
    (void)QtConcurrent::run([guard, generation, candidates]() {
        QList<ScanRecord> updates;
        updates.reserve(candidates.size());
        for (auto record : candidates) {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                break;
            }

            QString name = cachedResolvedName(record.ip, record.mac);
            if (name.isEmpty()) {
                name = reverseLookupName(record.ip);
            }
            if (name.isEmpty()) {
                continue;
            }

            record.hostName = name;
            record.vendor = name;
            rememberResolvedName(record.ip, record.mac, name);
            updates.append(record);
        }

        if (!guard) {
            return;
        }
        QMetaObject::invokeMethod(guard.data(), [guard, generation, candidates, updates]() {
            if (!guard) {
                return;
            }
            {
                QMutexLocker locker(&guard->m_nameEnrichmentMutex);
                for (const auto& record : candidates) {
                    guard->m_nameEnrichmentInFlight.remove(record.ip);
                }
            }
            if (guard->m_activeGeneration.load() != generation) {
                return;
            }

            for (auto updated : updates) {
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(updated.ip);
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        ScanRecord merged = liveIt.value();
                        if (isUnknownVendorLabel(merged.hostName)) {
                            merged.hostName = updated.hostName;
                        }
                        if (isUnknownVendorLabel(merged.vendor) || merged.vendor == liveIt->hostName) {
                            merged.vendor = merged.hostName;
                        }
                        mergeHelpfulScanFields(merged, updated);
                        guard->m_liveRecords.insert(updated.ip, merged);
                        updated = merged;
                    } else {
                        guard->m_liveRecords.insert(updated.ip, updated);
                    }
                }
                emit guard->recordReady(updated);
            }
        }, Qt::QueuedConnection);
    });
}

void NetworkScanService::startDetailEnrichment(const QList<ScanRecord>& records, quint64 generation, const QString& scanProfile) {
    QList<ScanRecord> candidates;
    candidates.reserve(records.size());
    for (const auto& record : records) {
        if (!record.ip.trimmed().isEmpty() && record.status != HostStatus::Offline) {
            candidates.append(record);
        }
    }
    if (candidates.isEmpty()) {
        return;
    }

    QPointer<NetworkScanService> guard(this);
    (void)QtConcurrent::run([guard, generation, candidates, scanProfile]() {
        QList<ScanRecord> updates;
        updates.reserve(candidates.size());
        const ScanTiming timing = scanTimingForProfile(scanProfile);
        const int polishPortTimeoutMs = qBound(220, timing.portTimeoutMs + 140, 750);

        for (auto record : candidates) {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }

            bool changed = false;
            const QString gateway = guard->cachedGateway();
            if ((record.gateway.trimmed().isEmpty()
                 || record.gateway == QStringLiteral("-")
                 || record.gateway == QStringLiteral("[n/a]"))
                && !gateway.trimmed().isEmpty()
                && gateway != QStringLiteral("-")) {
                record.gateway = gateway;
                changed = true;
            }

            if (record.mac.trimmed().isEmpty() || record.mac == QStringLiteral("-")) {
                const QString cachedMac = guard->prefetchedMacForIp(record.ip);
                const QString mac = (cachedMac.trimmed().isEmpty() || cachedMac == QStringLiteral("-"))
                    ? lookupMac(record.ip)
                    : cachedMac;
                if (!mac.trimmed().isEmpty() && mac != QStringLiteral("-")) {
                    record.mac = mac;
                    changed = true;
                }
            }

            const QStringList openPorts = probeOpenPorts(record.ip, polishPortTimeoutMs, scanProfile);
            if (!openPorts.isEmpty()) {
                const QString portsDisplay = openPorts.join(QLatin1Char(','));
                if (record.port != portsDisplay || record.portsDisplay != portsDisplay) {
                    record.port = portsDisplay;
                    record.portsDisplay = portsDisplay;
                    changed = true;
                }
                const QString webDetect = detectWebService(record.ip, openPorts);
                if (record.webDetect != webDetect) {
                    record.webDetect = webDetect;
                    changed = true;
                }
                const bool pingSuccess = !isMissingPingDisplay(record.pingDisplay);
                const QString typeHint = detectTypeHint(openPorts, pingSuccess, record.onLink);
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
            } else if (isUnknownVendorLabel(record.typeHint)) {
                const bool pingSuccess = !isMissingPingDisplay(record.pingDisplay);
                const QString typeHint = detectTypeHint({}, pingSuccess, record.onLink);
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
            }

            if (isUnknownVendorLabel(record.hostName)) {
                QString name = cachedResolvedName(record.ip, record.mac);
                if (name.isEmpty()) {
                    name = reverseLookupName(record.ip);
                }
                if (!name.isEmpty()) {
                    record.hostName = name;
                    record.vendor = name;
                    rememberResolvedName(record.ip, record.mac, name);
                    changed = true;
                }
            } else if (isUnknownVendorLabel(record.vendor)) {
                const QString vendor = vendorDisplayText(record.hostName, record.mac, guard->m_vendorDb);
                if (!isUnknownVendorLabel(vendor)) {
                    record.vendor = vendor;
                    changed = true;
                }
            }

            const QString routeName = routeDisplayForHost(guard->m_activeAdapter, record);
            if (record.name != routeName) {
                record.name = routeName;
                changed = true;
            }

            if (changed) {
                updates.append(record);
            }
        }

        if (!guard || updates.isEmpty()) {
            return;
        }
        QMetaObject::invokeMethod(guard.data(), [guard, generation, updates]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }
            for (auto updated : updates) {
                guard->publishLiveRecord(updated);
            }
        }, Qt::QueuedConnection);
    });
}

void NetworkScanService::publishLiveRecord(ScanRecord record) {
    if (m_cancelRequested.load()
        || record.ip.trimmed().isEmpty()
        || record.status == HostStatus::Offline
        || record.generation != m_activeGeneration.load()) {
        return;
    }

    {
        QMutexLocker locker(&m_liveRecordsMutex);
        const auto liveIt = m_liveRecords.constFind(record.ip);
        if (liveIt != m_liveRecords.constEnd()) {
            mergeHelpfulScanFields(record, liveIt.value());
        }
        m_liveRecords.insert(record.ip, record);
    }

    emit recordReady(record);

    const bool needsName = isUnknownVendorLabel(record.hostName)
        && (record.status == HostStatus::Online
            || !isUnknownVendorLabel(record.webDetect)
            || !isUnknownVendorLabel(record.portsDisplay)
            || (!record.mac.trimmed().isEmpty() && record.mac != QStringLiteral("-")));
    if (needsName) {
        startNameEnrichment({record}, record.generation);
    }
}

QString NetworkScanService::cachedGateway() const {
    QMutexLocker locker(&m_routeMutex);
    return m_cachedGateway;
}

void NetworkScanService::setCachedGateway(const QString& gateway) {
    const QString normalized = gateway.trimmed().isEmpty() ? QStringLiteral("-") : gateway.trimmed();
    QMutexLocker locker(&m_routeMutex);
    m_cachedGateway = normalized;
}

QString NetworkScanService::prefetchedMacForIp(const QString& ip) const {
    QMutexLocker locker(&m_prefetchedMacsMutex);
    return m_prefetchedMacs.value(ip, QStringLiteral("-"));
}

QHash<QString, QString> NetworkScanService::prefetchedMacsSnapshot() const {
    QMutexLocker locker(&m_prefetchedMacsMutex);
    return m_prefetchedMacs;
}

void NetworkScanService::setPrefetchedMacs(const QHash<QString, QString>& macs) {
    QMutexLocker locker(&m_prefetchedMacsMutex);
    m_prefetchedMacs = macs;
}

void NetworkScanService::mergePrefetchedMacs(const QHash<QString, QString>& macs) {
    if (macs.isEmpty()) {
        return;
    }
    QMutexLocker locker(&m_prefetchedMacsMutex);
    for (auto it = macs.constBegin(); it != macs.constEnd(); ++it) {
        if (!it.key().trimmed().isEmpty() && !it.value().trimmed().isEmpty() && it.value() != QStringLiteral("-")) {
            m_prefetchedMacs.insert(it.key(), it.value());
        }
    }
}

AdapterInfo NetworkScanService::adapterById(const QString& adapterId) const {
    const auto list = adapters();
    for (const auto& adapter : list) {
        if (adapter.id == adapterId || adapter.name == adapterId) {
            return adapter;
        }
    }
    return list.isEmpty() ? AdapterInfo{} : list.first();
}

ScanRecord NetworkScanService::probeHost(const QString& ip, const AdapterInfo& adapter, const QString& scanProfile) {
    const ScanTiming timing = scanTimingForProfile(scanProfile);
    ScanRecord row;
    row.ip = ip;
    row.generation = m_activeGeneration.load();
    row.gateway = cachedGateway();
    row.mask = m_cachedMask;
    row.onLink = isOnLink(ip, adapter);
    row.pingDisplay = QStringLiteral("[n/a]");
    row.portsDisplay = QStringLiteral("[n/a]");
    row.webDetect = QStringLiteral("[n/a]");
    row.name = QStringLiteral("-");
    row.vendor = QStringLiteral("unknown vendor");
    row.typeHint = QStringLiteral("[n/a]");
    row.speed = QStringLiteral("[n/a]");

    PingResult ping;
    QString resolvedName;
    QString prefetchedPingDisplay;
    row.mac = prefetchedMacForIp(ip);
    {
        QMutexLocker locker(&m_prefetchedPingMutex);
        const auto prefetchedPing = m_prefetchedPingDisplay.constFind(ip);
        if (prefetchedPing != m_prefetchedPingDisplay.constEnd()) {
            prefetchedPingDisplay = prefetchedPing.value();
        }
    }
    const bool usedPrefetchedPing = !prefetchedPingDisplay.isEmpty();
    if (usedPrefetchedPing) {
        ping.success = true;
        ping.display = prefetchedPingDisplay;
        resolvedName = cachedResolvedName(ip, row.mac);
    } else {
        ping = pingHost(ip, adapter.ip, timing.pingTimeoutMs);
        resolvedName = ping.resolvedName;
        if (ping.success && resolvedName.isEmpty()) {
            resolvedName = reverseLookupName(ip);
        }
    }
    row.pingDisplay = ping.display.isEmpty() ? QStringLiteral("[n/a]") : ping.display;

    QStringList openPorts;
    bool portsScanned = false;
    if (!ping.success && row.onLink && !row.mac.isEmpty() && row.mac != QStringLiteral("-")) {
        ping = retryPingHost(ip, adapter.ip, timing.pingTimeoutMs, timing.retryWindowMs, timing.retryIntervalMs);
        if (ping.success) {
            row.pingDisplay = ping.display;
        }
        if (resolvedName.isEmpty()) {
            resolvedName = ping.resolvedName;
        }
        if (ping.success && resolvedName.isEmpty()) {
            resolvedName = reverseLookupName(ip);
        }
    }

    if (!ping.success) {
        openPorts = probeOpenPorts(ip, timing.portTimeoutMs, scanProfile);
        portsScanned = true;
        if ((row.mac.isEmpty() || row.mac == QStringLiteral("-")) && (!openPorts.isEmpty() || row.onLink)) {
            row.mac = lookupMac(ip);
        }
        if (!ping.success && (!openPorts.isEmpty() || (!row.mac.isEmpty() && row.mac != QStringLiteral("-")))) {
            ping = retryPingHost(ip, adapter.ip, timing.pingTimeoutMs, timing.retryWindowMs, timing.retryIntervalMs);
            if (ping.success) {
                row.pingDisplay = ping.display;
            }
            if (resolvedName.isEmpty()) {
                resolvedName = ping.resolvedName;
            }
            if (ping.success && resolvedName.isEmpty()) {
                resolvedName = reverseLookupName(ip);
            }
        }
    }

    if (ping.success) {
        row.status = HostStatus::Online;
    } else if (row.onLink && !row.mac.isEmpty() && row.mac != QStringLiteral("-")) {
        row.status = HostStatus::Unknown;
    } else if (!openPorts.isEmpty()) {
        row.status = HostStatus::Unknown;
    } else {
        row.status = HostStatus::Offline;
    }

    row.vendor = resolvedName;
    if (row.status == HostStatus::Offline || m_cancelRequested.load()) {
        return row;
    }
    if (!portsScanned) {
        openPorts = probeOpenPorts(ip, timing.portTimeoutMs, scanProfile);
    }
    if ((row.mac.isEmpty() || row.mac == QStringLiteral("-")) && (ping.success || !openPorts.isEmpty() || row.onLink)) {
        row.mac = lookupMac(ip);
    }
    if (!openPorts.isEmpty()) {
        row.portsDisplay = openPorts.join(QLatin1Char(','));
        row.port = row.portsDisplay;
    } else {
        row.port = QStringLiteral("-");
    }

    const bool hasReachabilitySignal = ping.success
        || !openPorts.isEmpty()
        || (row.onLink && !row.mac.isEmpty() && row.mac != QStringLiteral("-"));
    if (resolvedName.isEmpty() && hasReachabilitySignal) {
        resolvedName = reverseLookupName(ip);
    }

    QString bestResolvedName = resolvedName;
    if (bestResolvedName.isEmpty()) {
        bestResolvedName = cachedResolvedName(row.ip, row.mac);
    }
    if (!bestResolvedName.isEmpty()) {
        rememberResolvedName(row.ip, row.mac, bestResolvedName);
    }
    row.hostName = bestResolvedName;
    row.vendor = vendorDisplayText(bestResolvedName, row.mac, m_vendorDb);
    row.name = routeDisplayForHost(adapter, row);
    row.webDetect = detectWebService(ip, openPorts);
    row.typeHint = detectTypeHint(openPorts, ping.success, row.onLink);
    row.speed = ping.success ? QStringLiteral("icmp") : QStringLiteral("link");
    return row;
}

NetworkScanService::PingResult NetworkScanService::retryPingHost(const QString& ip, const QString& sourceIp, int pingTimeoutMs, int windowMs, int intervalMs) {
    PingResult best;
    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + qMax(500, windowMs);
    while (QDateTime::currentMSecsSinceEpoch() < deadline) {
        auto ping = pingHost(ip, sourceIp, pingTimeoutMs);
        if (best.resolvedName.isEmpty()) {
            best.resolvedName = ping.resolvedName;
        }
        if (ping.success && !ping.display.trimmed().isEmpty()) {
            if (ping.resolvedName.isEmpty()) {
                ping.resolvedName = best.resolvedName;
            }
            return ping;
        }
        QThread::msleep(static_cast<unsigned long>(qMax(80, intervalMs)));
    }
    return best;
}

bool NetworkScanService::isVpnName(const QString& name) {
    static const QRegularExpression vpnRe(QStringLiteral("(tun|tap|wg|utun|tailscale|hamachi|nord|openvpn|vpn|clash|mihomo|wireguard|ppp)"),
                                          QRegularExpression::CaseInsensitiveOption);
    return vpnRe.match(name).hasMatch();
}

QList<QString> NetworkScanService::expandRange(const QString& startIp, const QString& endIp) {
    const quint32 start = ipToInt(startIp);
    const quint32 end = ipToInt(endIp);
    if (start == 0 || end == 0 || end < start) {
        return {};
    }
    QList<QString> result;
    result.reserve(static_cast<int>(end - start + 1));
    for (quint32 value = start; value <= end; ++value) {
        result.append(intToIp(value));
        if (value == 0xFFFFFFFFu) {
            break;
        }
    }
    return result;
}

quint32 NetworkScanService::ipToInt(const QString& ip) {
    const auto address = QHostAddress(ip);
    return address.protocol() == QAbstractSocket::IPv4Protocol ? address.toIPv4Address() : 0u;
}

QString NetworkScanService::intToIp(quint32 value) {
    return QHostAddress(value).toString();
}

NetworkScanService::PingResult NetworkScanService::pingHost(const QString& ip, const QString& sourceIp, int timeoutMs) {
    PingResult result;
    QStringList args;
    int exitStatus = -1;
#ifdef Q_OS_WIN
    args << QStringLiteral("-n") << QStringLiteral("1") << QStringLiteral("-w") << QString::number(qBound(250, timeoutMs, 2500));
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-S") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#elif defined(Q_OS_MACOS)
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QString::number(qBound(250, timeoutMs, 2500));
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-S") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#else
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QString::number(qBound(1, (timeoutMs + 999) / 1000, 3));
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-I") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#endif
    result.resolvedName = extractResolvedNameFromPingOutput(output, ip);

    static const QRegularExpression timeRe(QStringLiteral("(?:time|время)\\s*[=<]\\s*([0-9]+(?:[\\.,][0-9]+)?)\\s*(?:ms|мс)"),
                                           QRegularExpression::CaseInsensitiveOption);
    const auto match = timeRe.match(output);
    if (match.hasMatch()) {
        QString value = match.captured(1);
        value.replace(QLatin1Char(','), QLatin1Char('.'));
        const int pingMs = qMax(1, qRound(value.toDouble()));
        result.success = true;
        result.display = QStringLiteral("%1 ms").arg(pingMs);
        return result;
    }

    result.success = (exitStatus == 0);
    if (result.success) {
        result.display = QStringLiteral("online");
    }
    return result;
}

QHash<QString, QString> NetworkScanService::sweepPingRange(const QString& startIp, const QString& endIp, const AdapterInfo& adapter, const QString& scanProfile) {
    const ScanTiming timing = scanTimingForProfile(scanProfile);
    QHash<QString, QString> alive;
    QString fping = systemCommandPath(QStringLiteral("fping"));
    if (fping == QStringLiteral("fping")) {
        fping = QStandardPaths::findExecutable(QStringLiteral("fping"));
    }
    if (fping.isEmpty() || !QFileInfo::exists(fping)) {
        return alive;
    }

    const QList<QString> ips = expandRange(startIp, endIp);
    if (ips.isEmpty()) {
        return alive;
    }

    static const QRegularExpression lineRe(QStringLiteral("^\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s*:\\s*(.+)$"));
    static const QRegularExpression timeRe(QStringLiteral("([0-9]+(?:\\.[0-9]+)?)\\s*ms"),
                                           QRegularExpression::CaseInsensitiveOption);

    QStringList baseArgs {
        QStringLiteral("-C"), QStringLiteral("1"),
        QStringLiteral("-r0"),
        QStringLiteral("-t"), QString::number(timing.sweepTimeoutMs),
        QStringLiteral("-i"), QString::number(timing.sweepIntervalMs),
    };
#ifdef Q_OS_MACOS
    if (!adapter.ip.trimmed().isEmpty()) {
        baseArgs << QStringLiteral("-S") << adapter.ip.trimmed();
    }
#endif

    const int chunkSize = sweepChunkSizeForProfile(scanProfile);
    for (int index = 0; index < ips.size(); index += chunkSize) {
        QStringList args = baseArgs;
        const int limit = qMin(index + chunkSize, ips.size());
        for (int ipIndex = index; ipIndex < limit; ++ipIndex) {
            args << ips.at(ipIndex);
        }

        int exitStatus = -1;
        const QString output = runCommandCapture(fping, args, true, &exitStatus);
        Q_UNUSED(exitStatus)

        for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
            const auto lineMatch = lineRe.match(rawLine);
            if (!lineMatch.hasMatch()) {
                continue;
            }
            const QString ip = lineMatch.captured(1);
            const QString tail = lineMatch.captured(2).trimmed();
            if (tail.isEmpty()
                || tail == QStringLiteral("-")
                || tail.contains(QStringLiteral("timed out"), Qt::CaseInsensitive)) {
                continue;
            }
            const auto timeMatch = timeRe.match(tail);
            if (timeMatch.hasMatch()) {
                alive.insert(ip, QStringLiteral("%1 ms").arg(qMax(1, qRound(timeMatch.captured(1).toDouble()))));
                continue;
            }
            const QString compactDisplay = formatPingDisplay(tail);
            if (!compactDisplay.isEmpty()) {
                alive.insert(ip, compactDisplay);
            }
        }
    }
    return alive;
}

QStringList NetworkScanService::probeOpenPorts(const QString& ip, int timeoutMs, const QString& scanProfile) {
    const QList<quint16> ports = probePortsForProfile(scanProfile);
    QSet<quint16> openPortSet;
#ifdef Q_OS_WIN
    for (const auto port : ports) {
        if (tryConnectPort(ip, port, qBound(100, timeoutMs, 1000))) {
            openPortSet.insert(port);
        }
    }
#else
    struct PendingConnect {
        int fd {-1};
        quint16 port {0};
    };

    QList<PendingConnect> pending;
    const QByteArray ipBytes = ip.toUtf8();
    const int boundedTimeoutMs = qBound(90, timeoutMs, 1000);
    const qint64 deadlineMs = QDateTime::currentMSecsSinceEpoch() + boundedTimeoutMs;

    for (const auto port : ports) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }

        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        sockaddr_in addr {};
#ifdef __APPLE__
        addr.sin_len = sizeof(addr);
#endif
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, ipBytes.constData(), &addr.sin_addr) != 1) {
            ::close(fd);
            continue;
        }

        const int result = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (result == 0) {
            openPortSet.insert(port);
            ::close(fd);
            continue;
        }
        if (errno == EINPROGRESS && fd < FD_SETSIZE) {
            pending.append(PendingConnect{fd, port});
        } else {
            ::close(fd);
        }
    }

    while (!pending.isEmpty()) {
        const qint64 remainingMs = deadlineMs - QDateTime::currentMSecsSinceEpoch();
        if (remainingMs <= 0) {
            break;
        }

        fd_set writeSet;
        FD_ZERO(&writeSet);
        int maxFd = -1;
        for (const auto& item : pending) {
            FD_SET(item.fd, &writeSet);
            maxFd = qMax(maxFd, item.fd);
        }
        if (maxFd < 0) {
            break;
        }

        timeval timeout {};
        timeout.tv_sec = static_cast<long>(remainingMs / 1000);
        timeout.tv_usec = static_cast<int>((remainingMs % 1000) * 1000);
        const int ready = ::select(maxFd + 1, nullptr, &writeSet, nullptr, &timeout);
        if (ready <= 0) {
            break;
        }

        for (int index = pending.size() - 1; index >= 0; --index) {
            const auto item = pending.at(index);
            if (!FD_ISSET(item.fd, &writeSet)) {
                continue;
            }

            int socketError = 0;
            socklen_t errorLength = sizeof(socketError);
            if (::getsockopt(item.fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0 && socketError == 0) {
                openPortSet.insert(item.port);
            }
            ::close(item.fd);
            pending.removeAt(index);
        }
    }

    for (const auto& item : pending) {
        ::close(item.fd);
    }
#endif

    QStringList openPorts;
    for (const auto port : ports) {
        if (openPortSet.contains(port)) {
            openPorts.append(QString::number(port));
        }
    }
    return openPorts;
}

QString NetworkScanService::detectWebService(const QString& ip, const QStringList& openPorts) {
    if (containsValueInsensitive(openPorts, QStringLiteral("554"))) {
        return QStringLiteral("rtsp://%1:554").arg(ip);
    }
    QStringList endpoints;
    if (containsValueInsensitive(openPorts, QStringLiteral("443"))) {
        endpoints.append(QStringLiteral("https://%1").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8443"))) {
        endpoints.append(QStringLiteral("https://%1:8443").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("80"))) {
        endpoints.append(QStringLiteral("http://%1").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8080"))) {
        endpoints.append(QStringLiteral("http://%1:8080").arg(ip));
    }
    if (!endpoints.isEmpty()) {
        return endpoints.join(QStringLiteral(" | "));
    }
    return QStringLiteral("[n/a]");
}

QString NetworkScanService::lookupMac(const QString& ip) {
    int exitStatus = -1;
#ifdef Q_OS_LINUX
    const QString output = runCommandCapture(QStringLiteral("ip"), {QStringLiteral("neigh"), QStringLiteral("show"), ip}, false, &exitStatus);
#elif defined(Q_OS_MACOS)
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-n"), ip}, false, &exitStatus);
#else
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-a"), ip}, false, &exitStatus);
#endif
    if (exitStatus < 0) {
        return QStringLiteral("-");
    }

    static const QRegularExpression macRe(QStringLiteral("([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}|[0-9a-fA-F]{4}(?:\\.[0-9a-fA-F]{4}){2})"));
    const auto match = macRe.match(output);
    if (!match.hasMatch()) {
        return QStringLiteral("-");
    }

    return normalizeMacString(match.captured(1));
}

QHash<QString, QString> NetworkScanService::captureArpTable(const QString& adapterId) {
    QHash<QString, QString> entries;
    int exitStatus = -1;
#ifdef Q_OS_LINUX
    const QString output = runCommandCapture(QStringLiteral("ip"), {QStringLiteral("neigh"), QStringLiteral("show")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+dev\\s+(\\S+)\\s+lladdr\\s+([0-9a-fA-F:.\\-]+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        const QString ip = match.captured(1);
        const QString netif = match.captured(2);
        if (!adapterId.trimmed().isEmpty() && netif != adapterId) {
            continue;
        }
        entries.insert(ip, normalizeMacString(match.captured(3)));
    }
#elif defined(Q_OS_MACOS)
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-an")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^\\?\\s+\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)\\s+at\\s+([^\\s]+)\\s+on\\s+(\\S+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        const QString ip = match.captured(1);
        const QString macToken = match.captured(2);
        const QString netif = match.captured(3);
        if (!adapterId.trimmed().isEmpty() && netif != adapterId) {
            continue;
        }
        if (macToken.compare(QStringLiteral("(incomplete)"), Qt::CaseInsensitive) == 0) {
            continue;
        }
        entries.insert(ip, normalizeMacString(macToken));
    }
#else
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-a")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^(?:\\S+\\s+)?(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([0-9a-fA-F:.\\-]+)"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        entries.insert(match.captured(1), normalizeMacString(match.captured(2)));
    }
#endif
    return entries;
}

QString NetworkScanService::resolveName(const QString& ip) {
    const QString reverseName = reverseLookupName(ip);
    if (!reverseName.isEmpty()) {
        return reverseName;
    }
    const auto hostInfo = QHostInfo::fromName(ip);
    const QString normalized = normalizeResolvedName(hostInfo.hostName(), ip);
    return normalized.isEmpty() ? QStringLiteral("-") : normalized;
}

QString NetworkScanService::detectGateway(const AdapterInfo& adapter) {
#ifdef Q_OS_MACOS
    if (adapter.id.trimmed().isEmpty()) {
        return QStringLiteral("-");
    }

    static QMutex mutex;
    static QHash<QString, QString> cache;
    {
        QMutexLocker locker(&mutex);
        const auto cached = cache.constFind(adapter.id);
        if (cached != cache.constEnd()) {
            return cached.value();
        }
    }

    int exitStatus = -1;
    const QString output = runCommandCapture(QStringLiteral("netstat"), {QStringLiteral("-rn"), QStringLiteral("-f"), QStringLiteral("inet")}, false, &exitStatus);
    if (exitStatus < 0) {
        return QStringLiteral("-");
    }

    QHash<QString, QString> discovered;
    const QStringList lines = output.split(QLatin1Char('\n'));
    for (const QString& rawLine : lines) {
        const QString line = rawLine.simplified();
        if (line.isEmpty()
            || line.startsWith(QStringLiteral("Routing tables"))
            || line.startsWith(QStringLiteral("Internet"))
            || line.startsWith(QStringLiteral("Destination"))) {
            continue;
        }

        const QStringList parts = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (parts.size() < 4) {
            continue;
        }

        const QString destination = parts.at(0);
        const QString gateway = parts.at(1).trimmed();
        const QString netif = parts.at(3).trimmed();
        if (netif.isEmpty() || gateway.isEmpty() || gateway.startsWith(QStringLiteral("link#"))) {
            continue;
        }

        const bool prefer = destination == QStringLiteral("default");
        if (prefer || !discovered.contains(netif)) {
            discovered.insert(netif, gateway);
        }
    }

    {
        QMutexLocker locker(&mutex);
        for (auto it = discovered.begin(); it != discovered.end(); ++it) {
            cache.insert(it.key(), it.value());
        }
        return cache.value(adapter.id, QStringLiteral("-"));
    }
#else
    Q_UNUSED(adapter)
    return QStringLiteral("-");
#endif
}

QString NetworkScanService::detectMask(const AdapterInfo& adapter) {
    if (adapter.prefixLength <= 0) {
        return QStringLiteral("-");
    }
    quint32 mask = adapter.prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - adapter.prefixLength));
    return QHostAddress(mask).toString();
}

bool NetworkScanService::isOnLink(const QString& ip, const AdapterInfo& adapter) {
    if (adapter.ip.isEmpty() || adapter.prefixLength <= 0 || adapter.prefixLength > 32) {
        return false;
    }

    const quint32 hostIp = ipToInt(ip);
    const quint32 adapterIp = ipToInt(adapter.ip);
    if (hostIp == 0u || adapterIp == 0u) {
        return false;
    }

    const quint32 mask = adapter.prefixLength == 32 ? 0xFFFFFFFFu : (~0u << (32 - adapter.prefixLength));
    return (hostIp & mask) == (adapterIp & mask);
}

} // namespace nt
