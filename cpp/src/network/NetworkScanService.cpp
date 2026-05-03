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
    if (program == QStringLiteral("fping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
        const QString bundled = AppPaths::bundledToolPath(QStringLiteral("fping"));
        if (QFileInfo::exists(bundled)) return bundled;
    }
#elif defined(Q_OS_LINUX)
    if (program == QStringLiteral("ping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/ping"))) return QStringLiteral("/usr/bin/ping");
        if (QFileInfo::exists(QStringLiteral("/bin/ping"))) return QStringLiteral("/bin/ping");
    }
    if (program == QStringLiteral("fping")) {
        if (QFileInfo::exists(QStringLiteral("/usr/bin/fping"))) return QStringLiteral("/usr/bin/fping");
        if (QFileInfo::exists(QStringLiteral("/usr/sbin/fping"))) return QStringLiteral("/usr/sbin/fping");
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

struct CachedResolvedName {
    QString name;
    QString mac;
};

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

QList<QString> prioritizeIpsForScan(const QList<QString>& ips, const QHash<QString, QString>& knownMacs, const QString& gateway) {
    if (ips.isEmpty()) {
        return ips;
    }

    QList<QString> prioritized;
    prioritized.reserve(ips.size());
    QSet<QString> appended;

    const auto tryAppend = [&](const QString& ip) {
        if (!ip.isEmpty() && !appended.contains(ip) && ips.contains(ip)) {
            prioritized.append(ip);
            appended.insert(ip);
        }
    };

    tryAppend(gateway);

    QList<QString> knownIps;
    knownIps.reserve(knownMacs.size());
    for (auto it = knownMacs.constBegin(); it != knownMacs.constEnd(); ++it) {
        if (ips.contains(it.key())) {
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
    const double pingMs = value.trimmed().toDouble(&ok);
    if (!ok) {
        return {};
    }
    return QStringLiteral("%1 ms").arg(qMax(1, qRound(pingMs)));
}

QString detectTypeHint(const QStringList& openPorts, bool pingSuccess, bool onLink) {
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

QStringList resolveMdnsIpv4(const QString& hostName) {
    const QString output = runTimedCommandCapture(
        QStringLiteral("dscacheutil"),
        {QStringLiteral("-q"), QStringLiteral("host"), QStringLiteral("-a"), QStringLiteral("name"), hostName},
        1500,
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
    return ips;
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
               || serviceType == QStringLiteral("_companion-link._tcp")) {
        display = instanceName.trimmed();
    } else if (serviceType == QStringLiteral("_apple-mobdev2._tcp")) {
        if (display.isEmpty()) {
            display = instanceName.trimmed();
        }
    }

    display = display.trimmed();
    if (display.contains(QStringLiteral("supportsRP-"), Qt::CaseInsensitive)) {
        display = hostBase;
    }
    return normalizeResolvedName(display, QString());
}

QHash<QString, QString> collectBonjourNamesForService(const QSet<QString>& scannedIps, const QString& serviceType) {
    QHash<QString, QString> resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QString browseOutput = runTimedCommandCapture(
        QStringLiteral("dns-sd"),
        {QStringLiteral("-B"), serviceType, QStringLiteral("local")},
        700,
        true
    );
    const QStringList instances = parseDnsSdBrowseInstances(browseOutput, serviceType);
    for (const auto& instance : instances) {
        const QString lookupOutput = runTimedCommandCapture(
            QStringLiteral("dns-sd"),
            {QStringLiteral("-L"), instance, serviceType, QStringLiteral("local")},
            800,
            true
        );
        const QString targetHost = parseDnsSdLookupTarget(lookupOutput);
        if (targetHost.isEmpty()) {
            continue;
        }
        const QString displayName = prettyBonjourName(serviceType, instance, targetHost);
        if (displayName.isEmpty()) {
            continue;
        }
        const QStringList resolvedIps = resolveMdnsIpv4(targetHost);
        for (const auto& ip : resolvedIps) {
            if (!scannedIps.contains(ip) || resolved.contains(ip)) {
                continue;
            }
            resolved.insert(ip, displayName);
        }
    }
    return resolved;
}

QHash<QString, QString> collectBonjourNames(const QSet<QString>& scannedIps) {
    QHash<QString, QString> resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QStringList serviceTypes {
        QStringLiteral("_apple-mobdev2._tcp"),
        QStringLiteral("_airplay._tcp"),
        QStringLiteral("_raop._tcp"),
        QStringLiteral("_companion-link._tcp"),
    };

    QList<QFuture<QHash<QString, QString>>> futures;
    futures.reserve(serviceTypes.size());
    for (const auto& serviceType : serviceTypes) {
        futures.append(QtConcurrent::run([scannedIps, serviceType]() {
            return collectBonjourNamesForService(scannedIps, serviceType);
        }));
    }

    for (auto& future : futures) {
        future.waitForFinished();
        const auto partial = future.result();
        for (auto it = partial.constBegin(); it != partial.constEnd(); ++it) {
            if (!resolved.contains(it.key())) {
                resolved.insert(it.key(), it.value());
            }
        }
    }
    return resolved;
}

void warmArpCache(const QList<QString>& ips) {
    if (ips.isEmpty()) {
        return;
    }

    constexpr int kMaxWarmupIps = 2048;
    const QByteArray payload(1, '\0');
    QUdpSocket socket;

    for (int index = 0; index < ips.size() && index < kMaxWarmupIps; ++index) {
        const QHostAddress address(ips.at(index));
        if (address.protocol() != QAbstractSocket::IPv4Protocol) {
            continue;
        }
        socket.writeDatagram(payload, address, 9);
    }
}

} // namespace

NetworkScanService::NetworkScanService(VendorDbService* vendorDb, QObject* parent)
    : QObject(parent)
    , m_vendorDb(vendorDb)
    , m_watcher(new QFutureWatcher<nt::ScanRecord>(this)) {
    connect(m_watcher, &QFutureWatcher<nt::ScanRecord>::finished, this, [this]() {
        QList<ScanRecord> records;
        const auto future = m_watcher->future();
        const auto postScanMacs = captureArpTable(m_activeAdapter.id);
        m_prefetchedMacs = postScanMacs.isEmpty() ? m_prefetchedMacs : postScanMacs;
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
                record.gateway = record.gateway.trimmed().isEmpty() ? m_cachedGateway : record.gateway;
                record.mask = record.mask.trimmed().isEmpty() ? m_cachedMask : record.mask;
                if (isUnknownVendorLabel(record.vendor)) {
                    const QString cachedName = cachedResolvedName(record.ip, record.mac);
                    if (!cachedName.isEmpty()) {
                        record.vendor = cachedName;
                    }
                }
                record.vendor = vendorDisplayText(record.vendor, record.mac, m_vendorDb);
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
        emit scanFinished(records, durationMs);
        startRtspEnrichment(records, finishedGeneration);
    });
}

NetworkScanService::~NetworkScanService() {
    cancel();
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

void NetworkScanService::start(const QString& startIp, const QString& endIp, const QString& adapterId, int maxWorkers, quint64 generation) {
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
    QThreadPool::globalInstance()->setMaxThreadCount(qBound(8, maxWorkers, 96));
    m_activeAdapter = adapterById(adapterId);
    const auto adapter = m_activeAdapter;
    emit scanStarted();
    m_cachedGateway = detectGateway(adapter);
    m_cachedMask = detectMask(adapter);
    m_prefetchedMacs = captureArpTable(adapter.id);
    {
        QMutexLocker locker(&m_prefetchedPingMutex);
        m_prefetchedPingDisplay.clear();
    }
    const auto scheduledIps = prioritizeIpsForScan(ips, m_prefetchedMacs, m_cachedGateway);

    QList<QString> immediateProbeIps;
    immediateProbeIps.reserve(3);
    for (const auto& ip : scheduledIps) {
        if (immediateProbeIps.size() >= 3) {
            break;
        }
        const QString mac = m_prefetchedMacs.value(ip, QStringLiteral("-"));
        if (!mac.isEmpty() && mac != QStringLiteral("-")) {
            immediateProbeIps.append(ip);
        }
    }
    for (const auto& ip : scheduledIps) {
        if (immediateProbeIps.size() >= 3) {
            break;
        }
        if (!immediateProbeIps.contains(ip)) {
            immediateProbeIps.append(ip);
        }
    }

    QList<QString> onLinkIps;
    onLinkIps.reserve(scheduledIps.size());
    for (const auto& ip : scheduledIps) {
        if (isOnLink(ip, adapter) && ip != adapter.ip) {
            onLinkIps.append(ip);
        }
    }
    if (!onLinkIps.isEmpty()) {
        (void)QtConcurrent::run([onLinkIps]() {
            warmArpCache(onLinkIps);
        });
    }
#ifdef Q_OS_MACOS
    startBonjourEnrichment(scheduledIps, generation);
#endif

    const auto launchPrioritizedProbe = [this, adapter, generation](const QString& ip, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, ip]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run([this, adapter, generation, ip]() {
                if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                    return;
                }
                auto record = probeHost(ip, adapter);
                if (m_cancelRequested.load()
                    || record.ip.isEmpty()
                    || record.status == HostStatus::Offline
                    || record.generation != m_activeGeneration.load()) {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, record]() {
                    if (m_cancelRequested.load() || record.generation != m_activeGeneration.load()) {
                        return;
                    }
                    {
                        QMutexLocker locker(&m_liveRecordsMutex);
                        m_liveRecords.insert(record.ip, record);
                    }
                    emit recordReady(record);
                }, Qt::QueuedConnection);
            });
        });
    };

    for (int index = 0; index < immediateProbeIps.size(); ++index) {
        launchPrioritizedProbe(immediateProbeIps.at(index), index * 40);
    }

    const QSet<QString> immediateProbeSet(immediateProbeIps.constBegin(), immediateProbeIps.constEnd());
    (void)QtConcurrent::run([this, adapter, generation, startIp, endIp, scheduledIps, immediateProbeSet, launchPrioritizedProbe]() {
        const auto prefetchedPing = sweepPingRange(startIp, endIp, adapter);
        if (prefetchedPing.isEmpty()) {
            return;
        }

        QMetaObject::invokeMethod(this, [this, adapter, generation, scheduledIps, immediateProbeSet, prefetchedPing, launchPrioritizedProbe]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            {
                QMutexLocker locker(&m_prefetchedPingMutex);
                for (auto it = prefetchedPing.constBegin(); it != prefetchedPing.constEnd(); ++it) {
                    m_prefetchedPingDisplay.insert(it.key(), it.value());
                }
            }

            int launchIndex = 0;
            for (const auto& ip : scheduledIps) {
                if (launchIndex >= 6) {
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

    auto future = QtConcurrent::mapped(scheduledIps, [this, adapter](const QString& ip) {
        if (m_cancelRequested.load()) {
            return ScanRecord{};
        }
        auto record = probeHost(ip, adapter);
        if (!m_cancelRequested.load()
            && !record.ip.isEmpty()
            && record.status != HostStatus::Offline
            && record.generation == m_activeGeneration.load()) {
            QMetaObject::invokeMethod(this, [this, record]() {
                if (!m_cancelRequested.load() && record.generation == m_activeGeneration.load()) {
                    {
                        QMutexLocker locker(&m_liveRecordsMutex);
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
    QMutexLocker locker(&m_liveRecordsMutex);
    m_liveRecords.clear();
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
        if (!guard || bonjourNames.isEmpty()) {
            return;
        }
        QMetaObject::invokeMethod(guard.data(), [guard, generation, bonjourNames]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }
            for (auto it = bonjourNames.constBegin(); it != bonjourNames.constEnd(); ++it) {
                rememberResolvedName(it.key(), QString(), it.value());
                ScanRecord updated;
                bool shouldEmit = false;
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(it.key());
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        updated = liveIt.value();
                        updated.hostName = it.value();
                        updated.vendor = it.value();
                        guard->m_liveRecords.insert(it.key(), updated);
                        shouldEmit = true;
                    }
                }
                if (shouldEmit) {
                    emit guard->recordReady(updated);
                }
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
            if (updated.typeHint.trimmed().isEmpty()
                || updated.typeHint == QStringLiteral("-")
                || updated.typeHint == QStringLiteral("[n/a]")) {
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
            for (const auto& updated : updates) {
                emit guard->recordReady(updated);
            }
        }, Qt::QueuedConnection);
    });
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

ScanRecord NetworkScanService::probeHost(const QString& ip, const AdapterInfo& adapter) {
    ScanRecord row;
    row.ip = ip;
    row.generation = m_activeGeneration.load();
    row.gateway = m_cachedGateway;
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
    {
        QMutexLocker locker(&m_prefetchedPingMutex);
        const auto prefetchedPing = m_prefetchedPingDisplay.constFind(ip);
        if (prefetchedPing != m_prefetchedPingDisplay.constEnd()) {
            prefetchedPingDisplay = prefetchedPing.value();
        }
    }
    if (!prefetchedPingDisplay.isEmpty()) {
        ping.success = true;
        ping.display = prefetchedPingDisplay;
    } else {
        ping = pingHost(ip, adapter.ip);
        resolvedName = ping.resolvedName;
    }
    row.pingDisplay = ping.display.isEmpty() ? QStringLiteral("[n/a]") : ping.display;
    row.mac = m_prefetchedMacs.value(ip, QStringLiteral("-"));

    QStringList openPorts;
    bool portsScanned = false;
    if (!ping.success && row.onLink && !row.mac.isEmpty() && row.mac != QStringLiteral("-")) {
        ping = retryPingHost(ip, adapter.ip, 3000, 220);
        if (ping.success) {
            row.pingDisplay = ping.display;
        }
        if (resolvedName.isEmpty()) {
            resolvedName = ping.resolvedName;
        }
    }

    if (!ping.success) {
        openPorts = probeOpenPorts(ip);
        portsScanned = true;
        if ((row.mac.isEmpty() || row.mac == QStringLiteral("-")) && (!openPorts.isEmpty() || row.onLink)) {
            row.mac = lookupMac(ip);
        }
        if (!ping.success && (!openPorts.isEmpty() || (!row.mac.isEmpty() && row.mac != QStringLiteral("-")))) {
            ping = retryPingHost(ip, adapter.ip, 3000, 220);
            if (ping.success) {
                row.pingDisplay = ping.display;
            }
            if (resolvedName.isEmpty()) {
                resolvedName = ping.resolvedName;
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
        openPorts = probeOpenPorts(ip);
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

NetworkScanService::PingResult NetworkScanService::retryPingHost(const QString& ip, const QString& sourceIp, int windowMs, int intervalMs) {
    PingResult best;
    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + qMax(500, windowMs);
    while (QDateTime::currentMSecsSinceEpoch() < deadline) {
        auto ping = pingHost(ip, sourceIp);
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

NetworkScanService::PingResult NetworkScanService::pingHost(const QString& ip, const QString& sourceIp) {
    PingResult result;
    QStringList args;
    int exitStatus = -1;
#ifdef Q_OS_WIN
    args << QStringLiteral("-n") << QStringLiteral("1") << QStringLiteral("-w") << QStringLiteral("350");
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-S") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#elif defined(Q_OS_MACOS)
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QStringLiteral("350");
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-S") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#else
    args << QStringLiteral("-c") << QStringLiteral("1") << QStringLiteral("-W") << QStringLiteral("1");
    if (!sourceIp.isEmpty()) {
        args << QStringLiteral("-I") << sourceIp;
    }
    args << ip;
    const QString output = runCommandCapture(QStringLiteral("ping"), args, true, &exitStatus);
#endif
    result.resolvedName = extractResolvedNameFromPingOutput(output, ip);

    static const QRegularExpression timeRe(QStringLiteral("time[=<]([0-9]+(?:\\.[0-9]+)?)\\s*ms"),
                                           QRegularExpression::CaseInsensitiveOption);
    const auto match = timeRe.match(output);
    if (match.hasMatch()) {
        const int pingMs = qMax(1, qRound(match.captured(1).toDouble()));
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

QHash<QString, QString> NetworkScanService::sweepPingRange(const QString& startIp, const QString& endIp, const AdapterInfo& adapter) {
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
        QStringLiteral("-t180"),
        QStringLiteral("-i1"),
    };
#ifdef Q_OS_MACOS
    if (!adapter.ip.trimmed().isEmpty()) {
        baseArgs << QStringLiteral("-S") << adapter.ip.trimmed();
    }
#endif

    constexpr int chunkSize = 64;
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

QStringList NetworkScanService::probeOpenPorts(const QString& ip) {
    static const QList<quint16> ports {22, 80, 443};
    QStringList openPorts;
    for (const auto port : ports) {
        if (tryConnectPort(ip, port, 180)) {
            openPorts.append(QString::number(port));
        }
    }
    return openPorts;
}

QString NetworkScanService::detectWebService(const QString& ip, const QStringList& openPorts) {
    if (containsValueInsensitive(openPorts, QStringLiteral("554"))) {
        return QStringLiteral("rtsp://%1:554").arg(ip);
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("443"))) {
        return QStringLiteral("https://%1").arg(ip);
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("80"))) {
        return QStringLiteral("http://%1").arg(ip);
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
    const auto hostInfo = QHostInfo::fromName(ip);
    return hostInfo.hostName().trimmed().isEmpty() ? QStringLiteral("-") : hostInfo.hostName().trimmed();
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
