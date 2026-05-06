#include "network/NetworkScanService.h"

#include "core/AppPaths.h"
#include "core/VendorDbService.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
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
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QUrl>
#include <QtConcurrent>

#include <algorithm>
#include <array>

#ifndef Q_OS_WIN
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
    if (program == QStringLiteral("route")) return QStringLiteral("/sbin/route");
    if (program == QStringLiteral("ipconfig")) return QStringLiteral("/usr/sbin/ipconfig");
    if (program == QStringLiteral("smbutil")) return QStringLiteral("/usr/bin/smbutil");
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
    const auto finalize = [](const QString& normalized) {
        const QStringList parts = normalized.split(QLatin1Char(':'), Qt::SkipEmptyParts);
        if (parts.size() != 6) {
            return QStringLiteral("-");
        }
        bool ok = false;
        const int firstOctet = parts.first().toInt(&ok, 16);
        if (!ok || (firstOctet & 0x01) != 0) {
            return QStringLiteral("-");
        }
        bool allZero = true;
        bool allBroadcast = true;
        for (const auto& part : parts) {
            const int value = part.toInt(&ok, 16);
            if (!ok) {
                return QStringLiteral("-");
            }
            allZero = allZero && value == 0x00;
            allBroadcast = allBroadcast && value == 0xff;
        }
        if (allZero || allBroadcast) {
            return QStringLiteral("-");
        }
        return normalized;
    };

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
        return finalize(parts.join(QLatin1Char(':')));
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
        return finalize(parts.join(QLatin1Char(':')));
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
    return finalize(parts.join(QLatin1Char(':')));
}

QString normalizeGatewayIp(QString value) {
    value = value.trimmed();
    const auto address = QHostAddress(value);
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return QStringLiteral("-");
    }

    const quint32 ip = address.toIPv4Address();
    const quint8 first = static_cast<quint8>((ip >> 24) & 0xff);
    const quint8 last = static_cast<quint8>(ip & 0xff);
    if (ip == 0
        || ip == 0xffffffffu
        || first == 0
        || first == 127
        || first >= 224
        || (first == 169 && static_cast<quint8>((ip >> 16) & 0xff) == 254)
        || last == 0
        || last == 255) {
        return QStringLiteral("-");
    }
    return address.toString();
}

bool isValidGatewayIp(const QString& value) {
    return normalizeGatewayIp(value) != QStringLiteral("-");
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
        || normalized == QStringLiteral("?")
        || normalized == QStringLiteral("online");
}

bool isWeakTypeHint(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized == QStringLiteral("?")
        || normalized == QStringLiteral("icmp")
        || normalized == QStringLiteral("udp")
        || normalized == QStringLiteral("arp")
        || normalized == QStringLiteral("mdns")
        || normalized == QStringLiteral("ssdp")
        || normalized == QStringLiteral("upnp")
        || normalized == QStringLiteral("tcp");
}

void mergeHelpfulScanFields(ScanRecord& target, const ScanRecord& source) {
    if (target.ip.isEmpty() || source.ip.isEmpty() || target.ip != source.ip) {
        return;
    }

    if ((target.mac.trimmed().isEmpty() || target.mac == QStringLiteral("-"))
        && !source.mac.trimmed().isEmpty()
        && source.mac != QStringLiteral("-")) {
        const QString mac = normalizeMacString(source.mac);
        if (mac != QStringLiteral("-")) {
            target.mac = mac;
        }
    }

    if (isMissingPingDisplay(target.pingDisplay) && !isMissingPingDisplay(source.pingDisplay)) {
        target.pingDisplay = source.pingDisplay;
        if (source.status == HostStatus::Online) {
            target.status = HostStatus::Online;
        }
        if (isUnknownVendorLabel(target.speed) && !isUnknownVendorLabel(source.speed)) {
            target.speed = source.speed;
        }
        if ((isUnknownVendorLabel(target.typeHint) || (isWeakTypeHint(target.typeHint) && !isWeakTypeHint(source.typeHint)))
            && !isUnknownVendorLabel(source.typeHint)) {
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
    if ((isUnknownVendorLabel(target.typeHint) || (isWeakTypeHint(target.typeHint) && !isWeakTypeHint(source.typeHint)))
        && !isUnknownVendorLabel(source.typeHint)) {
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
        const QString gateway = normalizeGatewayIp(source.gateway);
        if (gateway != QStringLiteral("-")) {
            target.gateway = gateway;
        }
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
        || !isUnknownVendorLabel(record.portsDisplay)
        || !isUnknownVendorLabel(record.webDetect);
}

bool needsNameEnrichment(const ScanRecord& record) {
    return isUnknownVendorLabel(record.hostName)
        && (record.status == HostStatus::Online
            || !isUnknownVendorLabel(record.webDetect)
            || !isUnknownVendorLabel(record.portsDisplay)
            || (!record.mac.trimmed().isEmpty() && record.mac != QStringLiteral("-")));
}

bool needsDetailEnrichment(const ScanRecord& record) {
    if (record.ip.trimmed().isEmpty() || record.status == HostStatus::Offline) {
        return false;
    }
    return isMissingPingDisplay(record.pingDisplay)
        || record.port.trimmed().isEmpty()
        || record.port == QStringLiteral("-")
        || record.port == QStringLiteral("[n/a]")
        || record.portsDisplay.trimmed().isEmpty()
        || record.portsDisplay == QStringLiteral("-")
        || record.portsDisplay == QStringLiteral("[n/a]")
        || isUnknownVendorLabel(record.webDetect)
        || isUnknownVendorLabel(record.typeHint)
        || record.typeHint == QStringLiteral("icmp")
        || record.typeHint == QStringLiteral("udp")
        || record.typeHint == QStringLiteral("arp")
        || record.typeHint == QStringLiteral("mdns")
        || record.typeHint == QStringLiteral("ssdp")
        || record.mac.trimmed().isEmpty()
        || record.mac == QStringLiteral("-")
        || isUnknownVendorLabel(record.hostName)
        || record.gateway.trimmed().isEmpty()
        || record.gateway == QStringLiteral("-")
        || record.gateway == QStringLiteral("[n/a]");
}

int quickPingTimeoutForProfile(const QString& profile) {
    const QString normalized = profile.trimmed().toLower();
    if (normalized == QStringLiteral("fast")) {
        return 280;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 520;
    }
    return 360;
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
        return 44;
    }
    if (normalized == QStringLiteral("reliable")) {
        return 20;
    }
    return 32;
}

struct CachedResolvedName {
    QString name;
    QString mac;
};

struct BonjourResolution {
    QHash<QString, QString> namesByIp;
    QHash<QString, QString> namesByMac;
    QSet<QString> activeIps;
};

bool isEmptyBonjourResolution(const BonjourResolution& resolution) {
    return resolution.namesByIp.isEmpty() && resolution.namesByMac.isEmpty();
}

struct SsdpResolution {
    QHash<QString, QString> namesByIp;
    QHash<QString, QString> typesByIp;
    QHash<QString, QString> webByIp;
    QHash<QString, QString> portsByIp;
    QSet<QString> activeIps;
};

bool isEmptySsdpResolution(const SsdpResolution& resolution) {
    return resolution.activeIps.isEmpty()
        && resolution.namesByIp.isEmpty()
        && resolution.typesByIp.isEmpty()
        && resolution.webByIp.isEmpty();
}

void mergeDeviceResolution(SsdpResolution& target, const SsdpResolution& source) {
    for (auto it = source.namesByIp.constBegin(); it != source.namesByIp.constEnd(); ++it) {
        if (!target.namesByIp.contains(it.key())) {
            target.namesByIp.insert(it.key(), it.value());
        }
    }
    for (auto it = source.typesByIp.constBegin(); it != source.typesByIp.constEnd(); ++it) {
        if (!target.typesByIp.contains(it.key())) {
            target.typesByIp.insert(it.key(), it.value());
        }
    }
    for (auto it = source.webByIp.constBegin(); it != source.webByIp.constEnd(); ++it) {
        if (!target.webByIp.contains(it.key())) {
            target.webByIp.insert(it.key(), it.value());
        }
    }
    for (auto it = source.portsByIp.constBegin(); it != source.portsByIp.constEnd(); ++it) {
        if (!target.portsByIp.contains(it.key())) {
            target.portsByIp.insert(it.key(), it.value());
        }
    }
    for (const auto& ip : source.activeIps) {
        target.activeIps.insert(ip);
    }
}

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
        return ScanTiming{520, 2600, 190, 260, 230, 1};
    }
    if (normalized == QStringLiteral("reliable")) {
        return ScanTiming{1500, 7200, 360, 760, 700, 4};
    }
    return ScanTiming{900, 4600, 240, 480, 420, 2};
}

QList<quint16> probePortsForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return {22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 8080, 8443, 9100, 62078};
    }
    if (normalized == QStringLiteral("reliable")) {
        return {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 515, 548, 554, 587, 631, 993, 995, 1433, 1723, 1883, 2049, 2869, 3306, 3389, 3689, 5000, 5001, 5357, 5432, 5900, 6379, 7000, 8000, 8008, 8060, 8080, 8081, 8090, 8443, 8554, 8883, 8888, 9000, 9090, 9100, 9443, 10000, 49152, 62078};
    }
    return {22, 23, 53, 80, 111, 135, 139, 443, 445, 515, 548, 554, 631, 1433, 1883, 2869, 3389, 3689, 5000, 5001, 5357, 5900, 7000, 8000, 8008, 8060, 8080, 8081, 8090, 8443, 8554, 8888, 9000, 9090, 9100, 9443, 62078};
}

int workerCountForProfile(int requestedWorkers, const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return qBound(8, requestedWorkers, 64);
    }
    if (normalized == QStringLiteral("reliable")) {
        return qBound(2, requestedWorkers, 24);
    }
    return qBound(4, requestedWorkers, 48);
}

int enrichmentWorkerCountForProfile(const QString& profile) {
    const int ideal = qMax(4, QThread::idealThreadCount());
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return qBound(6, ideal * 2, 16);
    }
    if (normalized == QStringLiteral("reliable")) {
        return qBound(3, ideal, 8);
    }
    return qBound(4, ideal + 2, 12);
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

QStringList priorityBonjourServiceTypes() {
    return {
        QStringLiteral("_device-info._tcp"),
        QStringLiteral("_companion-link._tcp"),
        QStringLiteral("_airplay._tcp"),
        QStringLiteral("_raop._tcp"),
        QStringLiteral("_apple-mobdev2._tcp"),
        QStringLiteral("_workstation._tcp"),
        QStringLiteral("_ssh._tcp"),
        QStringLiteral("_http._tcp"),
        QStringLiteral("_https._tcp"),
    };
}

QStringList advertisedBonjourServiceTypes() {
#ifdef Q_OS_MACOS
    static QStringList cached;
    static bool loaded = false;
    if (loaded) {
        return cached;
    }
    loaded = true;

    const QString output = runTimedCommandCapture(
        QStringLiteral("dns-sd"),
        {QStringLiteral("-Q"), QStringLiteral("_services._dns-sd._udp.local"), QStringLiteral("PTR")},
        1800,
        true
    );
    static const QRegularExpression serviceRe(QStringLiteral("\\b(_[A-Za-z0-9][A-Za-z0-9_.\\-]*\\._(?:tcp|udp))\\.local\\.?"),
                                              QRegularExpression::CaseInsensitiveOption);
    auto it = serviceRe.globalMatch(output);
    while (it.hasNext()) {
        QString service = it.next().captured(1).toLower();
        if (!service.isEmpty() && !cached.contains(service)) {
            cached.append(service);
        }
    }
    return cached;
#else
    return {};
#endif
}

QStringList allBonjourServiceTypes() {
    QStringList services = priorityBonjourServiceTypes();
    const QStringList extraServices {
        QStringLiteral("_smb._tcp"),
        QStringLiteral("_afpovertcp._tcp"),
        QStringLiteral("_ipp._tcp"),
        QStringLiteral("_ipps._tcp"),
        QStringLiteral("_printer._tcp"),
        QStringLiteral("_pdl-datastream._tcp"),
        QStringLiteral("_print-caps._tcp"),
        QStringLiteral("_scanner._tcp"),
        QStringLiteral("_uscan._tcp"),
        QStringLiteral("_uscans._tcp"),
        QStringLiteral("_privet._tcp"),
        QStringLiteral("_http-alt._tcp"),
        QStringLiteral("_googlecast._tcp"),
        QStringLiteral("_mi-connect._udp"),
        QStringLiteral("_matter._tcp"),
        QStringLiteral("_matterc._udp"),
        QStringLiteral("_spotify-connect._tcp"),
        QStringLiteral("_sonos._tcp"),
        QStringLiteral("_sftp-ssh._tcp"),
        QStringLiteral("_rdp._tcp"),
        QStringLiteral("_rtsp._tcp"),
        QStringLiteral("_hap._tcp"),
        QStringLiteral("_homekit._tcp"),
        QStringLiteral("_touch-able._tcp"),
        QStringLiteral("_apple-pairable._tcp"),
        QStringLiteral("_sleep-proxy._udp"),
    };
    for (const auto& service : extraServices) {
        if (!services.contains(service)) {
            services.append(service);
        }
    }
    for (const auto& service : advertisedBonjourServiceTypes()) {
        if (!services.contains(service)) {
            services.append(service);
        }
    }
    return services;
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
        const QString key = ip.trimmed();
        const CachedResolvedName next {normalizedName, normalizedMac == QStringLiteral("-") ? QString() : normalizedMac};
        resolvedNameByIpCache().insert(key, next);
    }
    if (!normalizedMac.isEmpty() && normalizedMac != QStringLiteral("-")) {
        resolvedNameByMacCache().insert(normalizedMac, normalizedName);
    }
}

void rememberBonjourResolution(const BonjourResolution& resolution) {
    for (auto it = resolution.namesByMac.constBegin(); it != resolution.namesByMac.constEnd(); ++it) {
        rememberResolvedName(QString(), it.key(), it.value());
    }
    for (auto it = resolution.namesByIp.constBegin(); it != resolution.namesByIp.constEnd(); ++it) {
        rememberResolvedName(it.key(), QString(), it.value());
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

BonjourResolution collectMdnsNamesWithSocket(const QSet<QString>& scannedIps, const QStringList& serviceTypes, const QString& adapterId, int timeoutMs);
QString resolveMdnsPtrName(const QString& ip, const QString& adapterId, int timeoutMs);
QString resolveNetbiosName(const QString& ip, int timeoutMs);
QString resolveLlmnrPtrName(const QString& ip, int timeoutMs);
QString resolveSmbStatusName(const QString& ip, int timeoutMs);

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

bool isLikelyDnsHostName(QString value, const QString& ip) {
    value = normalizeResolvedName(value, ip);
    if (value.isEmpty()) {
        return false;
    }
    const QString lower = value.toLower();
    if (lower == QStringLiteral("dig")
        || lower == QStringLiteral("nslookup")
        || lower == QStringLiteral("server")
        || lower == QStringLiteral("address")
        || lower == QStringLiteral("timeout")
        || lower == QStringLiteral("nxdomain")
        || lower == QStringLiteral("status")
        || lower == QStringLiteral("query")
        || lower == QStringLiteral("answer")
        || lower == QStringLiteral("authority")
        || lower == QStringLiteral("additional")
        || lower == QStringLiteral("opcode")
        || lower == QStringLiteral("flags")
        || lower == QStringLiteral("localhost")
        || lower == QStringLiteral("localdomain")
        || lower.contains(QStringLiteral("timed out"))
        || lower.contains(QStringLiteral("no servers"))
        || lower.contains(QStringLiteral("global options"))
        || lower.contains(QStringLiteral("communications error"))
        || lower.contains(QStringLiteral("can't find"))
        || lower.contains(QStringLiteral("not found"))
        || lower.contains(QStringLiteral("answer:"))
        || lower.contains(QStringLiteral("authority:"))
        || lower.contains(QStringLiteral("opcode:"))
        || lower.contains(QStringLiteral("status:"))
        || lower.contains(QStringLiteral("<<>>"))
        || lower.startsWith(QLatin1Char(';'))) {
        return false;
    }
    static const QRegularExpression hostRe(QStringLiteral("^[A-Za-z0-9_][A-Za-z0-9_.\\-]{1,126}\\.?$"));
    if (!hostRe.match(value).hasMatch()) {
        return false;
    }
    if (!value.contains(QLatin1Char('.')) && value.size() < 3) {
        return false;
    }
    return true;
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
        const QString normalized = normalizeResolvedName(line.section(QLatin1Char('\t'), 0, 0).section(QLatin1Char(' '), 0, 0), ip);
        if (isLikelyDnsHostName(normalized, ip)) {
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
        if (isLikelyDnsHostName(normalized, ip)) {
            return normalized;
        }
    }

    return {};
}

void appendDnsU16(QByteArray& packet, quint16 value);
quint16 readDnsU16(const QByteArray& packet, int offset);
QByteArray encodeDnsName(QString name);
QString firstPtrNameFromDnsPacket(const QByteArray& packet, const QString& ip);
QString reverseMdnsNameForIp(const QString& ip);

QStringList localDnsServersForAdapter(const QString& adapterId) {
    QStringList servers;
#ifdef Q_OS_MACOS
    if (!adapterId.trimmed().isEmpty()) {
        const QString output = runTimedCommandCapture(QStringLiteral("ipconfig"), {QStringLiteral("getpacket"), adapterId.trimmed()}, 900, true);
        static const QRegularExpression dnsRe(QStringLiteral("domain_name_server\\s+\\([^)]*\\):\\s+\\{([^}]+)\\}"),
                                              QRegularExpression::CaseInsensitiveOption);
        const auto match = dnsRe.match(output);
        if (match.hasMatch()) {
            const QStringList values = match.captured(1).split(QRegularExpression(QStringLiteral("[,\\s]+")), Qt::SkipEmptyParts);
            for (const auto& value : values) {
                const QString ip = value.trimmed();
                if (QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol && !servers.contains(ip)) {
                    servers.append(ip);
                }
            }
        }
        static const QRegularExpression routerRe(QStringLiteral("router\\s+\\([^)]*\\):\\s+\\{([^}]+)\\}"),
                                                 QRegularExpression::CaseInsensitiveOption);
        const auto routerMatch = routerRe.match(output);
        if (routerMatch.hasMatch()) {
            const QStringList values = routerMatch.captured(1).split(QRegularExpression(QStringLiteral("[,\\s]+")), Qt::SkipEmptyParts);
            for (const auto& value : values) {
                const QString ip = value.trimmed();
                if (isValidGatewayIp(ip) && !servers.contains(ip)) {
                    servers.append(ip);
                }
            }
        }
    }
#else
    QFile resolv(QStringLiteral("/etc/resolv.conf"));
    if (resolv.open(QIODevice::ReadOnly)) {
        static const QRegularExpression nameserverRe(QStringLiteral("^\\s*nameserver\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)"),
                                                     QRegularExpression::MultilineOption);
        const QString text = QString::fromUtf8(resolv.readAll());
        auto it = nameserverRe.globalMatch(text);
        while (it.hasNext()) {
            const QString ip = it.next().captured(1);
            if (!servers.contains(ip)) {
                servers.append(ip);
            }
        }
    }
#endif
    return servers;
}

QByteArray buildDnsPtrQuery(const QString& ip, quint16 transactionId) {
    const QString reverseName = reverseMdnsNameForIp(ip);
    if (reverseName.isEmpty()) {
        return {};
    }
    QByteArray packet;
    packet.reserve(96);
    appendDnsU16(packet, transactionId);
    appendDnsU16(packet, 0x0100);
    appendDnsU16(packet, 1);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    packet.append(encodeDnsName(reverseName));
    appendDnsU16(packet, 12);
    appendDnsU16(packet, 1);
    return packet;
}

QString resolvePtrNameViaUdpDns(const QString& ip, const QString& server, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol
        || QHostAddress(server).protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress::AnyIPv4, 0)) {
        return {};
    }
    const quint16 transactionId = static_cast<quint16>((QDateTime::currentMSecsSinceEpoch() ^ qHash(ip) ^ qHash(server)) & 0xffff);
    const QByteArray query = buildDnsPtrQuery(ip, transactionId);
    if (query.isEmpty()) {
        return {};
    }

    const int boundedTimeout = qBound(260, timeoutMs, 1400);
    socket.writeDatagram(query, QHostAddress(server), 53);
    QElapsedTimer timer;
    timer.start();
    bool resent = false;
    while (timer.elapsed() < boundedTimeout) {
        if (!resent && timer.elapsed() > boundedTimeout / 2) {
            socket.writeDatagram(query, QHostAddress(server), 53);
            resent = true;
        }
        const int remaining = qMax(1, boundedTimeout - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(90, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            if (sender.toString() != server || datagram.size() < 12 || readDnsU16(datagram, 0) != transactionId) {
                continue;
            }
            const QString name = firstPtrNameFromDnsPacket(datagram, ip);
            if (isLikelyDnsHostName(name, ip)) {
                return normalizeResolvedName(name, ip);
            }
        }
    }
    return {};
}

QString resolvePtrNameViaServer(const QString& ip, const QString& server, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol
        || QHostAddress(server).protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    const QString udpName = resolvePtrNameViaUdpDns(ip, server, timeoutMs);
    if (!udpName.isEmpty()) {
        return udpName;
    }

    const QString dig = executableCommandPath(QStringLiteral("dig"));
    if (!dig.isEmpty()) {
        const QString output = runTimedCommandCapture(
            dig,
            {QStringLiteral("@%1").arg(server), QStringLiteral("+time=1"), QStringLiteral("+tries=1"), QStringLiteral("-x"), ip, QStringLiteral("+short")},
            qBound(500, timeoutMs, 1400),
            true
        );
        const QString normalized = firstResolvedNameFromLines(output, ip);
        if (!normalized.isEmpty()) {
            return normalized;
        }
    }

    const QString nslookup = executableCommandPath(QStringLiteral("nslookup"));
    if (!nslookup.isEmpty()) {
        const QString output = runTimedCommandCapture(nslookup, {ip, server}, qBound(500, timeoutMs, 1400), true);
        const QString normalized = parsePtrToolOutput(output, ip);
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
    const QString mdnsName = resolveMdnsPtrName(ip, QString(), 520);
    if (!mdnsName.isEmpty()) {
        return mdnsName;
    }

    const QString netbiosName = resolveNetbiosName(ip, 520);
    if (!netbiosName.isEmpty()) {
        return netbiosName;
    }

    const QString llmnrName = resolveLlmnrPtrName(ip, 520);
    if (!llmnrName.isEmpty()) {
        return llmnrName;
    }

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

QString resolveHostNameDeep(const QString& ip, const QString& adapterId, int timeoutMs) {
    const QString reverseName = reverseLookupName(ip);
    if (!reverseName.isEmpty()) {
        return reverseName;
    }

    const int boundedTimeout = qBound(280, timeoutMs, 1800);
    for (const auto& server : localDnsServersForAdapter(adapterId)) {
        const QString dnsName = resolvePtrNameViaServer(ip, server, boundedTimeout);
        if (!dnsName.isEmpty()) {
            return dnsName;
        }
    }

    const QString mdnsName = resolveMdnsPtrName(ip, adapterId, boundedTimeout);
    if (!mdnsName.isEmpty()) {
        return mdnsName;
    }

    const QString netbiosName = resolveNetbiosName(ip, qBound(260, boundedTimeout, 900));
    if (!netbiosName.isEmpty()) {
        return netbiosName;
    }

    const QString llmnrName = resolveLlmnrPtrName(ip, qBound(260, boundedTimeout, 900));
    if (!llmnrName.isEmpty()) {
        return llmnrName;
    }

    const QString smbName = resolveSmbStatusName(ip, qBound(350, boundedTimeout, 1200));
    if (!smbName.isEmpty()) {
        return smbName;
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

QString detectTypeHint(const QStringList& openPorts,
                       bool pingSuccess,
                       bool onLink,
                       const QString& hostName = QString(),
                       const QString& vendor = QString(),
                       const QString& mac = QString()) {
    const auto hasPort = [&](const QString& expected) {
        return std::any_of(openPorts.begin(), openPorts.end(), [&](const QString& value) {
            return value.trimmed().compare(expected, Qt::CaseInsensitive) == 0;
        });
    };

    const QString text = QStringList{hostName, vendor}.join(QLatin1Char(' ')).toLower();
    const QString normalizedMac = normalizeMacString(mac);

    if (hasPort(QStringLiteral("9100")) || hasPort(QStringLiteral("631")) || hasPort(QStringLiteral("515"))
        || text.contains(QStringLiteral("printer"))
        || text.contains(QStringLiteral("hp"))
        || text.contains(QStringLiteral("canon"))
        || text.contains(QStringLiteral("epson"))
        || text.contains(QStringLiteral("brother"))) {
        return QStringLiteral("printer");
    }
    if (hasPort(QStringLiteral("554")) || hasPort(QStringLiteral("8554"))
        || text.contains(QStringLiteral("camera"))
        || text.contains(QStringLiteral("rtsp"))) {
        return QStringLiteral("rtsp");
    }
    if (hasPort(QStringLiteral("3389"))) {
        return QStringLiteral("rdp");
    }
    if (hasPort(QStringLiteral("135")) || hasPort(QStringLiteral("139")) || hasPort(QStringLiteral("445"))
        || text.contains(QStringLiteral("windows"))
        || text.startsWith(QStringLiteral("win-"))
        || text.startsWith(QStringLiteral("desktop-"))) {
        return QStringLiteral("windows");
    }
    if (hasPort(QStringLiteral("548")) || hasPort(QStringLiteral("62078")) || hasPort(QStringLiteral("3689"))
        || text.contains(QStringLiteral("iphone"))
        || text.contains(QStringLiteral("ipad"))
        || text.contains(QStringLiteral("macbook"))
        || text.contains(QStringLiteral("mac mini"))
        || text.contains(QStringLiteral("imac"))
        || text.contains(QStringLiteral("apple"))
        || normalizedMac.startsWith(QStringLiteral("f0:c7:25"))
        || normalizedMac.startsWith(QStringLiteral("1c:f6:4c"))) {
        return QStringLiteral("apple");
    }
    if ((hasPort(QStringLiteral("445")) && (hasPort(QStringLiteral("5000")) || hasPort(QStringLiteral("5001"))))
        || text.contains(QStringLiteral("synology"))
        || text.contains(QStringLiteral("qnap"))
        || text.contains(QStringLiteral("nas"))) {
        return QStringLiteral("nas");
    }
    if (hasPort(QStringLiteral("5000")) || hasPort(QStringLiteral("5001")) || hasPort(QStringLiteral("7000"))
        || hasPort(QStringLiteral("8008")) || hasPort(QStringLiteral("8060"))
        || text.contains(QStringLiteral("airplay"))
        || text.contains(QStringLiteral("chromecast"))
        || text.contains(QStringLiteral("media"))) {
        return QStringLiteral("media");
    }
    if (hasPort(QStringLiteral("53"))
        || text.contains(QStringLiteral("router"))
        || text.contains(QStringLiteral("gateway"))
        || text.contains(QStringLiteral("wfadevice"))) {
        return QStringLiteral("gateway");
    }
    if (hasPort(QStringLiteral("1883")) || hasPort(QStringLiteral("8883"))
        || text.contains(QStringLiteral("tuya"))
        || text.contains(QStringLiteral("iot"))) {
        return QStringLiteral("iot");
    }
    if (hasPort(QStringLiteral("443")) || hasPort(QStringLiteral("8443")) || hasPort(QStringLiteral("9443"))
        || hasPort(QStringLiteral("80")) || hasPort(QStringLiteral("8080")) || hasPort(QStringLiteral("8081"))
        || hasPort(QStringLiteral("8090")) || hasPort(QStringLiteral("8888"))) {
        return QStringLiteral("web");
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
    if (!instances.isEmpty()) {
        return instances;
    }

    const QString serviceMarker = serviceType + QStringLiteral(".");
    const QStringList lines = output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const auto& rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (!line.contains(QStringLiteral(" Add "), Qt::CaseInsensitive)
            || !line.contains(serviceMarker, Qt::CaseInsensitive)) {
            continue;
        }
        const int markerIndex = line.indexOf(serviceMarker, 0, Qt::CaseInsensitive);
        if (markerIndex < 0) {
            continue;
        }
        const QString instance = line.mid(markerIndex + serviceMarker.size()).trimmed();
        if (!instance.isEmpty() && !instances.contains(instance)) {
            instances.append(instance);
        }
    }
    return instances;
}

QString parseDnsSdLookupTarget(const QString& output) {
    const QList<QRegularExpression> patterns {
        QRegularExpression(QStringLiteral("can be reached at\\s+([^\\s:]+)\\.:\\d+"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("can be reached at\\s+([^\\s:]+):\\d+"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("\\b(?:target|hostname)\\s*=\\s*([^\\s,;]+)"), QRegularExpression::CaseInsensitiveOption),
    };
    for (const auto& pattern : patterns) {
        const auto match = pattern.match(output);
        if (match.hasMatch()) {
            QString target = match.captured(1).trimmed();
            while (target.endsWith(QLatin1Char('.'))) {
                target.chop(1);
            }
            return target;
        }
    }
    return {};
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
        1900,
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
        1800,
        true
    ));
#else
    return ips;
#endif
}

QString ssdpHeaderValue(const QString& message, const QString& key) {
    const QString prefix = key + QLatin1Char(':');
    for (const auto& rawLine : message.split(QLatin1Char('\n'))) {
        const QString line = rawLine.trimmed();
        if (line.startsWith(prefix, Qt::CaseInsensitive)) {
            return line.mid(prefix.size()).trimmed();
        }
    }
    return {};
}

QString xmlTagValue(const QString& xml, const QString& tagName) {
    const QRegularExpression re(
        QStringLiteral("<\\s*%1\\s*>\\s*([^<]+)\\s*<\\s*/\\s*%1\\s*>")
            .arg(QRegularExpression::escape(tagName)),
        QRegularExpression::CaseInsensitiveOption
    );
    const auto match = re.match(xml);
    if (!match.hasMatch()) {
        return {};
    }
    QString value = match.captured(1).trimmed();
    value.replace(QStringLiteral("&amp;"), QStringLiteral("&"));
    value.replace(QStringLiteral("&lt;"), QStringLiteral("<"));
    value.replace(QStringLiteral("&gt;"), QStringLiteral(">"));
    value.replace(QStringLiteral("&quot;"), QStringLiteral("\""));
    value.replace(QStringLiteral("&apos;"), QStringLiteral("'"));
    return value;
}

QString fetchHttpText(const QUrl& url, int timeoutMs) {
    if (!url.isValid() || url.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) != 0 || url.host().trimmed().isEmpty()) {
        return {};
    }

    QTcpSocket socket;
    const int boundedTimeout = qBound(350, timeoutMs, 1600);
    socket.connectToHost(url.host(), static_cast<quint16>(url.port(80)));
    if (!socket.waitForConnected(boundedTimeout)) {
        return {};
    }

    QString path = url.path(QUrl::FullyEncoded);
    if (path.isEmpty()) {
        path = QStringLiteral("/");
    }
    const QString query = url.query(QUrl::FullyEncoded);
    if (!query.isEmpty()) {
        path += QLatin1Char('?') + query;
    }

    QByteArray request;
    request += "GET ";
    request += path.toUtf8();
    request += " HTTP/1.0\r\nHost: ";
    request += url.host().toUtf8();
    request += "\r\nUser-Agent: NetworkToolsQt/1.0.8\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    socket.write(request);
    if (!socket.waitForBytesWritten(boundedTimeout)) {
        return {};
    }

    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < boundedTimeout && response.size() < 96 * 1024) {
        if (!socket.waitForReadyRead(qMin(120, boundedTimeout - static_cast<int>(timer.elapsed())))) {
            if (socket.state() == QAbstractSocket::UnconnectedState) {
                break;
            }
            continue;
        }
        response += socket.readAll();
    }
    if (response.isEmpty()) {
        return {};
    }

    int bodyOffset = response.indexOf("\r\n\r\n");
    int separatorLength = 4;
    if (bodyOffset < 0) {
        bodyOffset = response.indexOf("\n\n");
        separatorLength = 2;
    }
    if (bodyOffset >= 0) {
        response = response.mid(bodyOffset + separatorLength);
    }
    return QString::fromUtf8(response);
}

QString ssdpTypeFromText(const QString& text) {
    const QString lower = text.toLower();
    if (lower.contains(QStringLiteral("internetgatewaydevice")) || lower.contains(QStringLiteral("wandevice"))) {
        return QStringLiteral("gateway");
    }
    if (lower.contains(QStringLiteral("printer")) || lower.contains(QStringLiteral("printbasic"))) {
        return QStringLiteral("printer");
    }
    if (lower.contains(QStringLiteral("camera")) || lower.contains(QStringLiteral("mediarenderer")) || lower.contains(QStringLiteral("rtsp"))) {
        return QStringLiteral("media");
    }
    if (lower.contains(QStringLiteral("mediaserver")) || lower.contains(QStringLiteral("dlna"))) {
        return QStringLiteral("media");
    }
    return QStringLiteral("upnp");
}

QString ssdpNameFromDescription(const QString& description, const QString& ip) {
    QString name = xmlTagValue(description, QStringLiteral("friendlyName"));
    if (name.isEmpty()) {
        const QString manufacturer = xmlTagValue(description, QStringLiteral("manufacturer"));
        const QString model = xmlTagValue(description, QStringLiteral("modelName"));
        name = QStringList{manufacturer, model}.join(QLatin1Char(' ')).simplified();
    }
    return normalizeResolvedName(name, ip);
}

QString xmlEntityDecode(QString value) {
    value.replace(QStringLiteral("&amp;"), QStringLiteral("&"));
    value.replace(QStringLiteral("&lt;"), QStringLiteral("<"));
    value.replace(QStringLiteral("&gt;"), QStringLiteral(">"));
    value.replace(QStringLiteral("&quot;"), QStringLiteral("\""));
    value.replace(QStringLiteral("&apos;"), QStringLiteral("'"));
    value.replace(QStringLiteral("&#45;"), QStringLiteral("-"));
    value.replace(QStringLiteral("&#95;"), QStringLiteral("_"));
    return value;
}

bool looksLikeDeviceName(QString value, const QString& ip) {
    value = xmlEntityDecode(value).trimmed().simplified();
    while (value.endsWith(QLatin1Char('.'))) {
        value.chop(1);
    }
    if (value.isEmpty()) {
        return false;
    }
    const QString normalized = normalizeResolvedName(value, ip);
    const QString lower = normalized.toLower();
    if (normalized.size() < 2
        || normalized.size() > 96
        || lower.isEmpty()
        || lower == QStringLiteral("unknown")
        || lower == QStringLiteral("unknown vendor")
        || lower == QStringLiteral("none")
        || lower == QStringLiteral("null")
        || lower == QStringLiteral("true")
        || lower == QStringLiteral("false")
        || lower == QStringLiteral("online")
        || lower == QStringLiteral("connected")
        || lower == QStringLiteral("active")
        || lower == QStringLiteral("device")
        || lower == QStringLiteral("localhost")
        || lower.startsWith(QStringLiteral("http://"))
        || lower.startsWith(QStringLiteral("https://"))
        || lower.contains(QStringLiteral("schemas.xmlsoap.org"))
        || lower.contains(QStringLiteral("w3.org"))
        || lower.contains(QStringLiteral("uuid:"))
        || lower.contains(QStringLiteral("urn:"))) {
        return false;
    }
    static const QRegularExpression macOnlyRe(QStringLiteral("^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$"), QRegularExpression::CaseInsensitiveOption);
    if (macOnlyRe.match(normalized).hasMatch()) {
        return false;
    }
    return true;
}

QString cleanDeviceNameCandidate(const QString& value, const QString& ip) {
    QString normalized = normalizeResolvedName(xmlEntityDecode(value).trimmed().simplified(), ip);
    if (looksLikeDeviceName(normalized, ip)) {
        return normalized;
    }
    return {};
}

QString nameFromTaggedText(const QString& text, const QString& ip) {
    const QStringList tagNames {
        QStringLiteral("friendlyName"),
        QStringLiteral("FriendlyName"),
        QStringLiteral("hostName"),
        QStringLiteral("hostname"),
        QStringLiteral("HostName"),
        QStringLiteral("deviceName"),
        QStringLiteral("DeviceName"),
        QStringLiteral("clientName"),
        QStringLiteral("ClientName"),
        QStringLiteral("computerName"),
        QStringLiteral("ComputerName"),
        QStringLiteral("name"),
        QStringLiteral("Name"),
    };
    for (const auto& tag : tagNames) {
        const QString value = xmlTagValue(text, tag);
        const QString cleaned = cleanDeviceNameCandidate(value, ip);
        if (!cleaned.isEmpty()) {
            return cleaned;
        }
    }

    const QList<QRegularExpression> patterns {
        QRegularExpression(QStringLiteral("\"(?:hostName|hostname|host_name|deviceName|device_name|clientName|client_name|computerName|computer_name|dnsName|dns_name|name)\"\\s*:\\s*\"([^\"]{2,96})\""),
                           QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("'(?:hostName|hostname|host_name|deviceName|device_name|clientName|client_name|computerName|computer_name|dnsName|dns_name|name)'\\s*:\\s*'([^']{2,96})'"),
                           QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("(?:hostName|hostname|host_name|deviceName|device_name|clientName|client_name|computerName|computer_name|dnsName|dns_name|name)\\s*[=:]\\s*['\"]?([^'\"<>,;\\r\\n]{2,96})"),
                           QRegularExpression::CaseInsensitiveOption),
    };
    for (const auto& pattern : patterns) {
        auto it = pattern.globalMatch(text);
        while (it.hasNext()) {
            const QString cleaned = cleanDeviceNameCandidate(it.next().captured(1), ip);
            if (!cleaned.isEmpty()) {
                return cleaned;
            }
        }
    }
    return {};
}

bool isCommonRouterToken(const QString& token) {
    const QString lower = token.toLower();
    static const QSet<QString> commonWords {
        QStringLiteral("http"), QStringLiteral("https"), QStringLiteral("html"), QStringLiteral("head"),
        QStringLiteral("body"), QStringLiteral("title"), QStringLiteral("meta"), QStringLiteral("link"),
        QStringLiteral("script"), QStringLiteral("style"), QStringLiteral("class"), QStringLiteral("table"),
        QStringLiteral("tbody"), QStringLiteral("thead"), QStringLiteral("tr"), QStringLiteral("td"),
        QStringLiteral("status"), QStringLiteral("online"), QStringLiteral("offline"), QStringLiteral("active"),
        QStringLiteral("inactive"), QStringLiteral("connected"), QStringLiteral("enabled"), QStringLiteral("disabled"),
        QStringLiteral("ethernet"), QStringLiteral("wireless"), QStringLiteral("wifi"), QStringLiteral("wlan"),
        QStringLiteral("lan"), QStringLiteral("wan"), QStringLiteral("dhcp"), QStringLiteral("lease"),
        QStringLiteral("device"), QStringLiteral("devices"), QStringLiteral("client"), QStringLiteral("clients"),
        QStringLiteral("host"), QStringLiteral("hosts"), QStringLiteral("hostname"), QStringLiteral("unknown"),
        QStringLiteral("vendor"), QStringLiteral("manufacturer"), QStringLiteral("model"), QStringLiteral("address"),
        QStringLiteral("gateway"), QStringLiteral("router"), QStringLiteral("server"), QStringLiteral("name"),
        QStringLiteral("login"), QStringLiteral("password"), QStringLiteral("authorization"), QStringLiteral("authorized"),
        QStringLiteral("unauthorized"), QStringLiteral("required"), QStringLiteral("realm"), QStringLiteral("basic"),
        QStringLiteral("digest"), QStringLiteral("error"), QStringLiteral("found"), QStringLiteral("file"),
        QStringLiteral("document"), QStringLiteral("window"), QStringLiteral("function"), QStringLiteral("return"),
        QStringLiteral("var"), QStringLiteral("const"), QStringLiteral("let"), QStringLiteral("true"),
        QStringLiteral("false"), QStringLiteral("null"), QStringLiteral("undefined"), QStringLiteral("dig"),
        QStringLiteral("nslookup"), QStringLiteral("query"), QStringLiteral("answer"), QStringLiteral("opcode")
    };
    return commonWords.contains(lower)
        || lower.contains(QStringLiteral("schemas"))
        || lower.contains(QStringLiteral("xml"))
        || lower.contains(QStringLiteral("http"))
        || lower.contains(QStringLiteral("www"));
}

QString fallbackNameTokenFromWindow(const QString& text, const QString& ip) {
    static const QRegularExpression tokenRe(QStringLiteral("\\b[A-Za-z][A-Za-z0-9_.\\-]{2,63}\\b"));

    QString normalized = text;
    normalized.replace(QRegularExpression(QStringLiteral("<[^>]+>")), QStringLiteral("\n"));
    normalized.replace(QRegularExpression(QStringLiteral("[{}\\[\\]\",;]")), QStringLiteral(" "));
    normalized.replace(QRegularExpression(QStringLiteral("\\s+")), QStringLiteral(" "));

    const int ipIndex = normalized.indexOf(ip);
    if (ipIndex < 0) {
        return {};
    }
    const int start = qMax(0, ipIndex - 180);
    const QString row = normalized.mid(start, qMin(420, normalized.size() - start));
    auto it = tokenRe.globalMatch(row);
    QStringList candidates;
    while (it.hasNext()) {
        const QString token = it.next().captured(0).trimmed();
        if (isCommonRouterToken(token)) {
            continue;
        }
        if (QHostAddress(token).protocol() == QAbstractSocket::IPv4Protocol || normalizeMacString(token) != QStringLiteral("-")) {
            continue;
        }
        static const QRegularExpression leaseTimeRe(QStringLiteral("^(?:\\d+[dhms]|day|days|hour|hours|min|mins|sec|secs)$"),
                                                    QRegularExpression::CaseInsensitiveOption);
        if (leaseTimeRe.match(token).hasMatch()) {
            continue;
        }
        const QString cleaned = cleanDeviceNameCandidate(token, ip);
        if (!cleaned.isEmpty()) {
            candidates.append(cleaned);
        }
    }

    std::sort(candidates.begin(), candidates.end(), [](const QString& left, const QString& right) {
        const auto score = [](const QString& value) {
            int result = value.size();
            if (value.contains(QLatin1Char('-')) || value.contains(QLatin1Char('_'))) result += 24;
            if (value.contains(QRegularExpression(QStringLiteral("[A-Z]"))) && value.contains(QRegularExpression(QStringLiteral("[a-z]")))) result += 12;
            if (value.contains(QRegularExpression(QStringLiteral("\\d")))) result += 8;
            if (value.contains(QStringLiteral("iphone"), Qt::CaseInsensitive)
                || value.contains(QStringLiteral("ipad"), Qt::CaseInsensitive)
                || value.contains(QStringLiteral("macbook"), Qt::CaseInsensitive)
                || value.contains(QStringLiteral("desktop"), Qt::CaseInsensitive)
                || value.contains(QStringLiteral("laptop"), Qt::CaseInsensitive)) {
                result += 18;
            }
            return result;
        };
        return score(left) > score(right);
    });
    if (!candidates.isEmpty()) {
        return candidates.first();
    }
    return {};
}

void parseNamesFromLooseText(const QString& text, const QSet<QString>& scannedIps, SsdpResolution& resolved) {
    if (text.isEmpty() || scannedIps.isEmpty()) {
        return;
    }
    for (const auto& ip : scannedIps) {
        qsizetype index = text.indexOf(ip);
        while (index >= 0) {
            const qsizetype start = qMax<qsizetype>(0, index - 1400);
            const QString window = text.mid(start, qMin<qsizetype>(2800, text.size() - start));
            QString name = nameFromTaggedText(window, ip);
            if (name.isEmpty()) {
                name = fallbackNameTokenFromWindow(window, ip);
            }
            if (!name.isEmpty()) {
                resolved.activeIps.insert(ip);
                if (!resolved.namesByIp.contains(ip)) {
                    resolved.namesByIp.insert(ip, name);
                }
                break;
            }
            index = text.indexOf(ip, index + ip.size());
        }
    }
}

SsdpResolution collectSsdpDevices(const QSet<QString>& scannedIps, const QString& adapterId, int timeoutMs) {
    SsdpResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress::AnyIPv4, 0, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        return resolved;
    }

    const QNetworkInterface iface = QNetworkInterface::interfaceFromName(adapterId);
    if (iface.isValid()) {
        socket.setMulticastInterface(iface);
    }
    socket.setSocketOption(QAbstractSocket::MulticastTtlOption, 2);

    const QHostAddress ssdpGroup(QStringLiteral("239.255.255.250"));
    const QList<QByteArray> searchTargets {
        QByteArrayLiteral("ssdp:all"),
        QByteArrayLiteral("upnp:rootdevice"),
        QByteArrayLiteral("urn:schemas-upnp-org:device:Basic:1"),
        QByteArrayLiteral("urn:schemas-upnp-org:device:MediaRenderer:1"),
        QByteArrayLiteral("urn:schemas-upnp-org:device:MediaServer:1"),
        QByteArrayLiteral("urn:schemas-upnp-org:device:Printer:1"),
        QByteArrayLiteral("urn:schemas-upnp-org:device:Scanner:1"),
        QByteArrayLiteral("urn:dial-multiscreen-org:service:dial:1"),
    };

    QHash<QString, QString> rawByIp;
    QHash<QString, QString> locationByIp;
    const auto sendQuery = [&]() {
        for (const auto& st : searchTargets) {
            QByteArray query;
            query += "M-SEARCH * HTTP/1.1\r\n";
            query += "HOST: 239.255.255.250:1900\r\n";
            query += "MAN: \"ssdp:discover\"\r\n";
            query += "MX: 1\r\n";
            query += "ST: ";
            query += st;
            query += "\r\n\r\n";
            socket.writeDatagram(query, ssdpGroup, 1900);
            QThread::msleep(1);
        }
    };

    QElapsedTimer timer;
    timer.start();
    sendQuery();
    bool sentRefresh = false;
    bool sentLateRefresh = false;
    while (timer.elapsed() < timeoutMs) {
        if (!sentRefresh && timer.elapsed() > 650) {
            sendQuery();
            sentRefresh = true;
        }
        if (!sentLateRefresh && timer.elapsed() > 1250) {
            sendQuery();
            sentLateRefresh = true;
        }
        const int remaining = qMax(1, timeoutMs - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(100, remaining))) {
            continue;
        }

        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            const QString ip = sender.toString();
            if (!scannedIps.contains(ip)) {
                continue;
            }
            const QString message = QString::fromUtf8(datagram);
            resolved.activeIps.insert(ip);
            rawByIp.insert(ip, message);
            const QString location = ssdpHeaderValue(message, QStringLiteral("LOCATION"));
            if (!location.isEmpty() && !locationByIp.contains(ip)) {
                locationByIp.insert(ip, location);
                resolved.webByIp.insert(ip, location);
                const QUrl url(location);
                if (url.isValid() && !url.host().isEmpty()) {
                    const int port = url.port(url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0 ? 443 : 80);
                    if (port > 0) {
                        resolved.portsByIp.insert(ip, QString::number(port));
                    }
                }
            }
        }
    }

    int fetchedDescriptions = 0;
    for (auto it = rawByIp.constBegin(); it != rawByIp.constEnd(); ++it) {
        const QString ip = it.key();
        QString typeText = it.value();
        const QString location = locationByIp.value(ip);
        QString name = nameFromTaggedText(typeText, ip);
        if (!location.isEmpty() && fetchedDescriptions < 48) {
            const QString description = fetchHttpText(QUrl(location), 700);
            if (!description.isEmpty()) {
                ++fetchedDescriptions;
                if (name.isEmpty()) {
                    name = ssdpNameFromDescription(description, ip);
                }
                if (name.isEmpty()) {
                    name = nameFromTaggedText(description, ip);
                }
                typeText += QLatin1Char('\n') + description.left(4096);
            }
        }
        if (!name.isEmpty()) {
            resolved.namesByIp.insert(ip, name);
        }
        resolved.typesByIp.insert(ip, ssdpTypeFromText(typeText));
    }

    return resolved;
}

QString wsDiscoveryTypeFromText(const QString& text) {
    const QString lower = text.toLower();
    if (lower.contains(QStringLiteral("printer")) || lower.contains(QStringLiteral("printdevice"))) {
        return QStringLiteral("printer");
    }
    if (lower.contains(QStringLiteral("scanner")) || lower.contains(QStringLiteral("scan"))) {
        return QStringLiteral("printer");
    }
    if (lower.contains(QStringLiteral("networkvideotransmitter")) || lower.contains(QStringLiteral("onvif")) || lower.contains(QStringLiteral("camera"))) {
        return QStringLiteral("media");
    }
    if (lower.contains(QStringLiteral("computer")) || lower.contains(QStringLiteral("windows"))) {
        return QStringLiteral("windows");
    }
    return QStringLiteral("wsd");
}

QString nameFromWsDiscoveryScopes(const QString& scopes, const QString& ip) {
    const QStringList parts = scopes.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
    for (QString part : parts) {
        part = QUrl::fromPercentEncoding(part.toUtf8());
        const QString lower = part.toLower();
        const QStringList markers {
            QStringLiteral("/thisdevice/name/"),
            QStringLiteral("/device/name/"),
            QStringLiteral("/name/"),
            QStringLiteral("onvif.org/name/")
        };
        for (const auto& marker : markers) {
            const int markerIndex = lower.indexOf(marker);
            if (markerIndex < 0) {
                continue;
            }
            QString candidate = part.mid(markerIndex + marker.size());
            const int nextSlash = candidate.indexOf(QLatin1Char('/'));
            if (nextSlash > 0) {
                candidate = candidate.left(nextSlash);
            }
            const QString cleaned = cleanDeviceNameCandidate(candidate, ip);
            if (!cleaned.isEmpty()) {
                return cleaned;
            }
        }
    }
    return {};
}

QStringList wsDiscoveryXAddrs(const QString& text) {
    QStringList urls;
    static const QRegularExpression xaddrRe(QStringLiteral("<(?:\\w+:)?XAddrs[^>]*>([^<]+)</(?:\\w+:)?XAddrs>"),
                                            QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    auto it = xaddrRe.globalMatch(text);
    while (it.hasNext()) {
        const QStringList parts = it.next().captured(1).split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const auto& part : parts) {
            const QUrl url(part.trimmed());
            if (url.isValid() && url.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0 && !urls.contains(url.toString())) {
                urls.append(url.toString());
            }
        }
    }
    return urls;
}

SsdpResolution collectWsDiscoveryDevices(const QSet<QString>& scannedIps, const QString& adapterId, int timeoutMs) {
    SsdpResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress::AnyIPv4, 0, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        return resolved;
    }
    const QNetworkInterface iface = QNetworkInterface::interfaceFromName(adapterId);
    if (iface.isValid()) {
        socket.setMulticastInterface(iface);
    }
    socket.setSocketOption(QAbstractSocket::MulticastTtlOption, 2);

    const QString messageId = QStringLiteral("uuid:%1-%2")
        .arg(QDateTime::currentMSecsSinceEpoch())
        .arg(QRandomGenerator::global()->generate());
    const QByteArray probe = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">"
        "<e:Header>"
        "<w:MessageID>%1</w:MessageID>"
        "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
        "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
        "</e:Header>"
        "<e:Body><d:Probe/></e:Body>"
        "</e:Envelope>").arg(messageId).toUtf8();

    const QHostAddress wsdGroup(QStringLiteral("239.255.255.250"));
    const auto sendProbe = [&]() {
        socket.writeDatagram(probe, wsdGroup, 3702);
    };

    QHash<QString, QString> rawByIp;
    QElapsedTimer timer;
    timer.start();
    sendProbe();
    bool sentRefresh = false;
    while (timer.elapsed() < timeoutMs) {
        if (!sentRefresh && timer.elapsed() > 700) {
            sendProbe();
            sentRefresh = true;
        }
        const int remaining = qMax(1, timeoutMs - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(100, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            const QString ip = sender.toString();
            if (!scannedIps.contains(ip)) {
                continue;
            }
            resolved.activeIps.insert(ip);
            rawByIp.insert(ip, QString::fromUtf8(datagram));
        }
    }

    int fetched = 0;
    for (auto it = rawByIp.constBegin(); it != rawByIp.constEnd(); ++it) {
        const QString ip = it.key();
        const QString text = it.value();
        QString name = nameFromTaggedText(text, ip);
        static const QRegularExpression scopesRe(QStringLiteral("<(?:\\w+:)?Scopes[^>]*>([^<]+)</(?:\\w+:)?Scopes>"),
                                                 QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
        const auto scopesMatch = scopesRe.match(text);
        if (name.isEmpty() && scopesMatch.hasMatch()) {
            name = nameFromWsDiscoveryScopes(scopesMatch.captured(1), ip);
        }
        for (const auto& xaddr : wsDiscoveryXAddrs(text)) {
            if (fetched >= 32 || !name.isEmpty()) {
                break;
            }
            const QString detail = fetchHttpText(QUrl(xaddr), 650);
            ++fetched;
            if (!detail.isEmpty()) {
                name = nameFromTaggedText(detail, ip);
            }
        }
        if (!name.isEmpty()) {
            resolved.namesByIp.insert(ip, name);
        }
        resolved.typesByIp.insert(ip, wsDiscoveryTypeFromText(text));
        const QStringList xaddrs = wsDiscoveryXAddrs(text);
        if (!xaddrs.isEmpty()) {
            resolved.webByIp.insert(ip, xaddrs.first());
            const QUrl url(xaddrs.first());
            const int port = url.port(80);
            if (port > 0) {
                resolved.portsByIp.insert(ip, QString::number(port));
            }
        }
    }
    return resolved;
}

SsdpResolution collectRouterDhcpHints(const QSet<QString>& scannedIps, const QString& gateway, int timeoutMs) {
    SsdpResolution resolved;
    if (scannedIps.isEmpty() || !isValidGatewayIp(gateway)) {
        return resolved;
    }

    const QStringList paths {
        QStringLiteral("/"),
        QStringLiteral("/status.htm"),
        QStringLiteral("/status.html"),
        QStringLiteral("/status.asp"),
        QStringLiteral("/lan.asp"),
        QStringLiteral("/LAN.html"),
        QStringLiteral("/dhcp.htm"),
        QStringLiteral("/dhcp.html"),
        QStringLiteral("/DHCPTable.asp"),
        QStringLiteral("/Main_DHCPStatus_Content.asp"),
        QStringLiteral("/userRpm/AssignedIpAddrListRpm.htm"),
        QStringLiteral("/cgi-bin/luci/admin/status/overview"),
        QStringLiteral("/api/devices"),
        QStringLiteral("/api/hosts"),
        QStringLiteral("/api/lan/hosts"),
        QStringLiteral("/api/dhcp/leases"),
        QStringLiteral("/devices"),
        QStringLiteral("/hosts"),
        QStringLiteral("/clients.json"),
    };

    QElapsedTimer timer;
    timer.start();
    int fetched = 0;
    for (const auto& path : paths) {
        if (timer.elapsed() >= timeoutMs || fetched >= 12) {
            break;
        }
        const QUrl url(QStringLiteral("http://%1%2").arg(gateway, path));
        const QString body = fetchHttpText(url, qBound(260, timeoutMs / 4, 650));
        ++fetched;
        if (body.isEmpty() || body.size() > 512 * 1024) {
            continue;
        }
        parseNamesFromLooseText(body, scannedIps, resolved);
        if (!resolved.namesByIp.isEmpty()) {
            break;
        }
    }
    return resolved;
}

SsdpResolution collectLibimobiledeviceNames(const QSet<QString>& scannedIps, const QHash<QString, QString>& knownMacs) {
    SsdpResolution resolved;
    if (scannedIps.isEmpty() || executableCommandPath(QStringLiteral("idevice_id")).isEmpty() || executableCommandPath(QStringLiteral("ideviceinfo")).isEmpty()) {
        return resolved;
    }

    const QString idsOutput = runTimedCommandCapture(QStringLiteral("idevice_id"), {QStringLiteral("-n"), QStringLiteral("-l")}, 1600, true);
    const QStringList ids = idsOutput.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
    int queried = 0;
    for (const auto& id : ids) {
        if (queried >= 16) {
            break;
        }
        ++queried;
        const QString name = cleanDeviceNameCandidate(
            runTimedCommandCapture(QStringLiteral("ideviceinfo"), {QStringLiteral("-n"), QStringLiteral("-u"), id, QStringLiteral("-k"), QStringLiteral("DeviceName")}, 1300, true),
            QString()
        );
        if (name.isEmpty()) {
            continue;
        }
        const QString wifiMac = normalizeMacString(
            runTimedCommandCapture(QStringLiteral("ideviceinfo"), {QStringLiteral("-n"), QStringLiteral("-u"), id, QStringLiteral("-k"), QStringLiteral("WiFiAddress")}, 1300, true)
        );
        if (wifiMac == QStringLiteral("-")) {
            continue;
        }
        for (auto it = knownMacs.constBegin(); it != knownMacs.constEnd(); ++it) {
            if (!scannedIps.contains(it.key())) {
                continue;
            }
            if (normalizeMacString(it.value()) == wifiMac) {
                resolved.activeIps.insert(it.key());
                resolved.namesByIp.insert(it.key(), name);
                resolved.typesByIp.insert(it.key(), QStringLiteral("apple"));
            }
        }
    }
    return resolved;
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

void appendDnsU16(QByteArray& packet, quint16 value) {
    packet.append(static_cast<char>((value >> 8) & 0xff));
    packet.append(static_cast<char>(value & 0xff));
}

quint16 readDnsU16(const QByteArray& packet, int offset) {
    if (offset < 0 || offset + 2 > packet.size()) {
        return 0;
    }
    return static_cast<quint16>((static_cast<quint8>(packet.at(offset)) << 8)
                                | static_cast<quint8>(packet.at(offset + 1)));
}

QByteArray encodeDnsName(QString name) {
    name = name.trimmed();
    while (name.endsWith(QLatin1Char('.'))) {
        name.chop(1);
    }

    QByteArray encoded;
    const QStringList labels = name.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    for (const auto& label : labels) {
        const QByteArray bytes = label.toUtf8();
        if (bytes.isEmpty()) {
            continue;
        }
        encoded.append(static_cast<char>(qMin(bytes.size(), 63)));
        encoded.append(bytes.constData(), qMin(bytes.size(), 63));
    }
    encoded.append('\0');
    return encoded;
}

QString decodeDnsName(const QByteArray& packet, int& offset) {
    QStringList labels;
    int cursor = offset;
    bool jumped = false;
    int jumps = 0;

    while (cursor >= 0 && cursor < packet.size() && jumps < 16) {
        const quint8 length = static_cast<quint8>(packet.at(cursor));
        if (length == 0) {
            if (!jumped) {
                offset = cursor + 1;
            }
            return labels.join(QLatin1Char('.'));
        }

        if ((length & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.size()) {
                return {};
            }
            const int pointer = ((length & 0x3f) << 8) | static_cast<quint8>(packet.at(cursor + 1));
            if (!jumped) {
                offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            ++jumps;
            continue;
        }

        if ((length & 0xc0) != 0 || cursor + 1 + length > packet.size()) {
            return {};
        }
        labels.append(QString::fromUtf8(packet.constData() + cursor + 1, length));
        cursor += 1 + length;
        if (!jumped) {
            offset = cursor;
        }
    }
    return {};
}

QByteArray buildMdnsQuery(const QString& name, quint16 type) {
    QByteArray packet;
    packet.reserve(64 + name.size());
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 1);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    packet.append(encodeDnsName(name));
    appendDnsU16(packet, type);
    appendDnsU16(packet, 0x8001);
    return packet;
}

QByteArray buildMdnsPtrQuery(const QString& name) {
    return buildMdnsQuery(name, 12);
}

QByteArray buildMdnsSrvQuery(const QString& name) {
    return buildMdnsQuery(name, 33);
}

QByteArray buildMdnsAQuery(const QString& name) {
    return buildMdnsQuery(name, 1);
}

QString serviceTypeFromDnsName(QString name) {
    name = name.trimmed();
    while (name.endsWith(QLatin1Char('.'))) {
        name.chop(1);
    }
    const QStringList labels = name.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (labels.size() < 2
        || !labels.at(0).startsWith(QLatin1Char('_'))
        || (labels.at(1) != QStringLiteral("_tcp") && labels.at(1) != QStringLiteral("_udp"))) {
        return {};
    }
    return labels.at(0) + QLatin1Char('.') + labels.at(1);
}

QString instanceNameFromServiceName(QString fullName, const QString& serviceType) {
    fullName = fullName.trimmed();
    while (fullName.endsWith(QLatin1Char('.'))) {
        fullName.chop(1);
    }
    const QString suffix = QLatin1Char('.') + serviceType + QStringLiteral(".local");
    if (fullName.endsWith(suffix, Qt::CaseInsensitive)) {
        fullName.chop(suffix.size());
    }
    return fullName.trimmed();
}

QString reverseMdnsNameForIp(const QString& ip) {
    const QStringList parts = ip.split(QLatin1Char('.'));
    if (parts.size() != 4) {
        return {};
    }
    return QStringLiteral("%1.%2.%3.%4.in-addr.arpa")
        .arg(parts.at(3), parts.at(2), parts.at(1), parts.at(0));
}

QString ipFromReverseMdnsName(QString name) {
    name = name.trimmed().toLower();
    while (name.endsWith(QLatin1Char('.'))) {
        name.chop(1);
    }
    const QString suffix = QStringLiteral(".in-addr.arpa");
    if (!name.endsWith(suffix)) {
        return {};
    }
    name.chop(suffix.size());
    const QStringList parts = name.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (parts.size() != 4) {
        return {};
    }
    const QString ip = QStringLiteral("%1.%2.%3.%4").arg(parts.at(3), parts.at(2), parts.at(1), parts.at(0));
    return QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol ? ip : QString();
}

QString firstPtrNameFromDnsPacket(const QByteArray& packet, const QString& ip) {
    if (packet.size() < 12) {
        return {};
    }

    int offset = 12;
    const quint16 questionCount = readDnsU16(packet, 4);
    const quint16 answerCount = readDnsU16(packet, 6);
    const quint16 authorityCount = readDnsU16(packet, 8);
    const quint16 additionalCount = readDnsU16(packet, 10);
    for (quint16 index = 0; index < questionCount; ++index) {
        decodeDnsName(packet, offset);
        offset += 4;
        if (offset > packet.size()) {
            return {};
        }
    }

    const int recordCount = answerCount + authorityCount + additionalCount;
    for (int index = 0; index < recordCount; ++index) {
        decodeDnsName(packet, offset);
        if (offset + 10 > packet.size()) {
            return {};
        }
        const quint16 type = readDnsU16(packet, offset);
        offset += 2;
        offset += 2;
        offset += 4;
        const quint16 dataLength = readDnsU16(packet, offset);
        offset += 2;
        if (offset + dataLength > packet.size()) {
            return {};
        }
        if (type == 12) {
            int nameOffset = offset;
            const QString normalized = normalizeResolvedName(decodeDnsName(packet, nameOffset), ip);
            if (!normalized.isEmpty()) {
                return normalized;
            }
        }
        offset += dataLength;
    }
    return {};
}

QString resolveMdnsPtrName(const QString& ip, const QString& adapterId, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }
    QSet<QString> target;
    target.insert(ip);
    const auto resolved = collectMdnsNamesWithSocket(target, {}, adapterId, qBound(300, timeoutMs, 1800));
    return normalizeResolvedName(resolved.namesByIp.value(ip), ip);
}

QByteArray encodedNetbiosName(const QString& rawName, quint8 suffix) {
    QByteArray padded(16, ' ');
    const QByteArray source = rawName.trimmed().isEmpty()
        ? QByteArray("*")
        : rawName.left(15).toLatin1().toUpper();
    for (int index = 0; index < source.size() && index < 15; ++index) {
        padded[index] = source.at(index);
    }
    padded[15] = static_cast<char>(suffix);

    QByteArray encoded;
    encoded.reserve(34);
    encoded.append(static_cast<char>(32));
    for (const auto byte : padded) {
        const quint8 value = static_cast<quint8>(byte);
        encoded.append(static_cast<char>('A' + ((value >> 4) & 0x0f)));
        encoded.append(static_cast<char>('A' + (value & 0x0f)));
    }
    encoded.append('\0');
    return encoded;
}

QByteArray buildNetbiosNodeStatusQuery(quint16 transactionId) {
    QByteArray packet;
    packet.reserve(64);
    appendDnsU16(packet, transactionId);
    appendDnsU16(packet, 0x0000);
    appendDnsU16(packet, 1);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    packet.append(encodedNetbiosName(QStringLiteral("*"), 0x00));
    appendDnsU16(packet, 0x0021);
    appendDnsU16(packet, 0x0001);
    return packet;
}

QString cleanNetbiosName(QString name) {
    name = name.trimmed();
    name.remove(QRegularExpression(QStringLiteral("[^A-Za-z0-9_. -]")));
    const QString lower = name.toLower();
    if (name.isEmpty()
        || lower == QStringLiteral("workgroup")
        || lower == QStringLiteral("local")
        || lower.contains(QStringLiteral("msbrowse"))) {
        return {};
    }
    return name;
}

QString parseNetbiosNodeStatusName(const QByteArray& packet, quint16 transactionId, const QString& ip) {
    if (packet.size() < 12 || readDnsU16(packet, 0) != transactionId) {
        return {};
    }

    int offset = 12;
    const quint16 questionCount = readDnsU16(packet, 4);
    const quint16 answerCount = readDnsU16(packet, 6);
    for (quint16 index = 0; index < questionCount; ++index) {
        decodeDnsName(packet, offset);
        offset += 4;
        if (offset > packet.size()) {
            return {};
        }
    }

    QString workstationName;
    QString serverName;
    for (quint16 answer = 0; answer < answerCount; ++answer) {
        decodeDnsName(packet, offset);
        if (offset + 10 > packet.size()) {
            return {};
        }
        const quint16 type = readDnsU16(packet, offset);
        offset += 2;
        offset += 2;
        offset += 4;
        const quint16 dataLength = readDnsU16(packet, offset);
        offset += 2;
        if (offset + dataLength > packet.size()) {
            return {};
        }
        if (type == 0x0021 && dataLength > 1) {
            const int count = static_cast<quint8>(packet.at(offset));
            for (int index = 0; index < count; ++index) {
                const int entryOffset = offset + 1 + (index * 18);
                if (entryOffset + 18 > offset + dataLength || entryOffset + 18 > packet.size()) {
                    break;
                }
                const QString name = cleanNetbiosName(QString::fromLatin1(packet.constData() + entryOffset, 15));
                if (name.isEmpty()) {
                    continue;
                }
                const quint8 suffix = static_cast<quint8>(packet.at(entryOffset + 15));
                const quint16 flags = readDnsU16(packet, entryOffset + 16);
                const bool groupName = (flags & 0x8000u) != 0;
                if (groupName) {
                    continue;
                }
                if (suffix == 0x20 && serverName.isEmpty()) {
                    serverName = name;
                } else if (suffix == 0x00 && workstationName.isEmpty()) {
                    workstationName = name;
                }
            }
        }
        offset += dataLength;
    }

    const QString best = !serverName.isEmpty() ? serverName : workstationName;
    return normalizeResolvedName(best, ip);
}

QString resolveNetbiosName(const QString& ip, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress::AnyIPv4, 0)) {
        return {};
    }
    const quint16 transactionId = static_cast<quint16>((QDateTime::currentMSecsSinceEpoch() ^ qHash(ip)) & 0xffff);
    const QByteArray query = buildNetbiosNodeStatusQuery(transactionId);
    socket.writeDatagram(query, QHostAddress(ip), 137);

    QElapsedTimer timer;
    timer.start();
    const int boundedTimeout = qBound(250, timeoutMs, 900);
    while (timer.elapsed() < boundedTimeout) {
        const int remaining = qMax(1, boundedTimeout - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(90, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            if (sender.toString() != ip) {
                continue;
            }
            const QString name = parseNetbiosNodeStatusName(datagram, transactionId, ip);
            if (!name.isEmpty()) {
                return name;
            }
        }
    }
    return {};
}

QByteArray buildUnicastDnsQuery(const QString& name, quint16 type, quint16 transactionId) {
    QByteArray packet;
    packet.reserve(64 + name.size());
    appendDnsU16(packet, transactionId);
    appendDnsU16(packet, 0x0000);
    appendDnsU16(packet, 1);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    appendDnsU16(packet, 0);
    packet.append(encodeDnsName(name));
    appendDnsU16(packet, type);
    appendDnsU16(packet, 0x0001);
    return packet;
}

QString resolveLlmnrPtrName(const QString& ip, int timeoutMs) {
    const QString reverseName = reverseMdnsNameForIp(ip);
    if (reverseName.isEmpty()) {
        return {};
    }

    QUdpSocket socket;
    if (!socket.bind(QHostAddress::AnyIPv4, 0)) {
        return {};
    }
    const quint16 transactionId = static_cast<quint16>((QDateTime::currentMSecsSinceEpoch() ^ qHash(ip) ^ 0x5355) & 0xffff);
    const QByteArray query = buildUnicastDnsQuery(reverseName, 12, transactionId);
    socket.writeDatagram(query, QHostAddress(ip), 5355);

    QElapsedTimer timer;
    timer.start();
    const int boundedTimeout = qBound(250, timeoutMs, 900);
    while (timer.elapsed() < boundedTimeout) {
        const int remaining = qMax(1, boundedTimeout - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(90, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            if (sender.toString() != ip || readDnsU16(datagram, 0) != transactionId) {
                continue;
            }
            const QString name = firstPtrNameFromDnsPacket(datagram, ip);
            if (!name.isEmpty()) {
                return name;
            }
        }
    }
    return {};
}

QString resolveSmbStatusName(const QString& ip, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol
        || executableCommandPath(QStringLiteral("smbutil")).isEmpty()) {
        return {};
    }

    const QString output = runTimedCommandCapture(
        QStringLiteral("smbutil"),
        {QStringLiteral("status"), QStringLiteral("-ae"), ip},
        qBound(500, timeoutMs, 1500),
        true
    );
    if (output.isEmpty()) {
        return {};
    }

    const QList<QRegularExpression> patterns {
        QRegularExpression(QStringLiteral("^\\s*(?:Server|NetBIOS\\s+Name|Workstation|Name)\\s*[:=]\\s*([^\\r\\n]{2,64})$"),
                           QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption),
        QRegularExpression(QStringLiteral("^\\s*([A-Za-z0-9_.\\-]{2,64})\\s+<00>\\s+UNIQUE\\b"),
                           QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption),
        QRegularExpression(QStringLiteral("Got\\s+response\\s+from\\s+([^\\s:]{2,64})"),
                           QRegularExpression::CaseInsensitiveOption),
    };
    for (const auto& pattern : patterns) {
        auto it = pattern.globalMatch(output);
        while (it.hasNext()) {
            const QString candidate = it.next().captured(1).trimmed();
            if (candidate == ip || isCommonRouterToken(candidate)) {
                continue;
            }
            const QString cleaned = cleanDeviceNameCandidate(candidate, ip);
            if (!cleaned.isEmpty()) {
                return cleaned;
            }
        }
    }
    return {};
}

QByteArray appleLockdownGetValueRequest(const QString& key) {
    const QByteArray body = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict>"
        "<key>Label</key><string>NetworkToolsQt</string>"
        "<key>Request</key><string>GetValue</string>"
        "<key>Key</key><string>%1</string>"
        "</dict></plist>").arg(key).toUtf8();
    QByteArray packet;
    packet.reserve(body.size() + 4);
    appendDnsU16(packet, static_cast<quint16>((body.size() >> 16) & 0xffff));
    appendDnsU16(packet, static_cast<quint16>(body.size() & 0xffff));
    packet.append(body);
    return packet;
}

QString parseAppleLockdownValue(const QByteArray& payload, const QString& ip) {
    const QString text = QString::fromUtf8(payload);
    static const QRegularExpression valueRe(
        QStringLiteral("<key>\\s*Value\\s*</key>\\s*<string>([^<]+)</string>"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption
    );
    const auto match = valueRe.match(text);
    if (match.hasMatch()) {
        return normalizeResolvedName(xmlEntityDecode(match.captured(1).trimmed()), ip);
    }

    static const QRegularExpression stringRe(
        QStringLiteral("<string>([^<]{2,96})</string>"),
        QRegularExpression::CaseInsensitiveOption
    );
    auto stringIt = stringRe.globalMatch(text);
    while (stringIt.hasNext()) {
        const QString normalized = normalizeResolvedName(xmlEntityDecode(stringIt.next().captured(1).trimmed()), ip);
        const QString lower = normalized.toLower();
        if (!normalized.isEmpty()
            && lower != QStringLiteral("networktoolsqt")
            && lower != QStringLiteral("getvalue")
            && lower != QStringLiteral("success")) {
            return normalized;
        }
    }

    const QString latin = QString::fromLatin1(payload);
    const int marker = latin.indexOf(QStringLiteral("Value"), 0, Qt::CaseInsensitive);
    if (marker >= 0) {
        static const QRegularExpression printableRe(QStringLiteral("[A-Za-z0-9][A-Za-z0-9_. '\\-]{2,80}"));
        auto it = printableRe.globalMatch(latin.mid(marker + 5));
        while (it.hasNext()) {
            const QString normalized = normalizeResolvedName(it.next().captured(0).trimmed(), ip);
            const QString lower = normalized.toLower();
            if (!normalized.isEmpty()
                && lower != QStringLiteral("devicename")
                && lower != QStringLiteral("value")
                && lower != QStringLiteral("success")) {
                return normalized;
            }
        }
    }
    return {};
}

QString resolveAppleLockdownName(const QString& ip, int timeoutMs) {
    if (QHostAddress(ip).protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    QTcpSocket socket;
    const int boundedTimeout = qBound(280, timeoutMs, 850);
    socket.connectToHost(ip, 62078);
    if (!socket.waitForConnected(boundedTimeout)) {
        return {};
    }

    const QByteArray request = appleLockdownGetValueRequest(QStringLiteral("DeviceName"));
    socket.write(request);
    if (!socket.waitForBytesWritten(boundedTimeout)) {
        return {};
    }

    QByteArray header;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < boundedTimeout && header.size() < 4) {
        if (!socket.waitForReadyRead(qMin(80, boundedTimeout - static_cast<int>(timer.elapsed())))) {
            continue;
        }
        header += socket.read(4 - header.size());
    }
    if (header.size() != 4) {
        return {};
    }

    const quint32 length = (static_cast<quint32>(static_cast<quint8>(header.at(0))) << 24)
        | (static_cast<quint32>(static_cast<quint8>(header.at(1))) << 16)
        | (static_cast<quint32>(static_cast<quint8>(header.at(2))) << 8)
        | static_cast<quint32>(static_cast<quint8>(header.at(3)));
    if (length == 0 || length > 256 * 1024) {
        return {};
    }

    QByteArray payload;
    payload.reserve(static_cast<int>(length));
    while (timer.elapsed() < boundedTimeout && payload.size() < static_cast<int>(length)) {
        if (!socket.waitForReadyRead(qMin(80, boundedTimeout - static_cast<int>(timer.elapsed())))) {
            continue;
        }
        payload += socket.read(static_cast<int>(length) - payload.size());
    }
    if (payload.isEmpty()) {
        return {};
    }
    return parseAppleLockdownValue(payload, ip);
}

QList<QString> sortedIpsForMdnsReverse(const QSet<QString>& scannedIps, int limit) {
    QList<QString> ips(scannedIps.constBegin(), scannedIps.constEnd());
    std::sort(ips.begin(), ips.end(), [](const QString& left, const QString& right) {
        return QHostAddress(left).toIPv4Address() < QHostAddress(right).toIPv4Address();
    });
    if (ips.size() > limit) {
        ips = ips.mid(0, limit);
    }
    return ips;
}

struct MdnsResolutionState {
    BonjourResolution resolved;
    QHash<QString, QString> serviceByInstance;
    QHash<QString, QString> instanceByFullName;
    QHash<QString, QString> targetByInstance;
    QHash<QString, QString> nameByInstance;
    QHash<QString, QStringList> ipsByHost;
    QSet<QString> queriedSrvInstances;
    QSet<QString> queriedHosts;
};

QString bestNameFromTxtRecord(const QByteArray& data, const QString& ip) {
    QStringList values;
    int offset = 0;
    while (offset < data.size()) {
        const int length = static_cast<quint8>(data.at(offset));
        ++offset;
        if (length <= 0 || offset + length > data.size()) {
            break;
        }
        values.append(QString::fromUtf8(data.constData() + offset, length));
        offset += length;
    }

    const QStringList preferredKeys {
        QStringLiteral("fn"),
        QStringLiteral("name"),
        QStringLiteral("device_name"),
        QStringLiteral("devicename"),
        QStringLiteral("hostname"),
        QStringLiteral("host"),
        QStringLiteral("ty"),
        QStringLiteral("model"),
    };
    for (const auto& key : preferredKeys) {
        for (const auto& value : values) {
            const int equals = value.indexOf(QLatin1Char('='));
            if (equals <= 0) {
                continue;
            }
            const QString currentKey = value.left(equals).trimmed().toLower();
            if (currentKey != key) {
                continue;
            }
            const QString cleaned = cleanDeviceNameCandidate(value.mid(equals + 1), ip);
            if (!cleaned.isEmpty()) {
                return cleaned;
            }
        }
    }
    return {};
}

void materializeMdnsState(const QSet<QString>& scannedIps, MdnsResolutionState& state) {
    for (auto it = state.serviceByInstance.constBegin(); it != state.serviceByInstance.constEnd(); ++it) {
        const QString key = it.key();
        const QString serviceType = it.value();
        const QString instanceName = state.instanceByFullName.value(key);
        const QString targetHost = state.targetByInstance.value(key);
        QString displayName = state.nameByInstance.value(key);
        if (displayName.isEmpty()) {
            displayName = prettyBonjourName(serviceType, instanceName, targetHost);
        }
        if (displayName.isEmpty()) {
            continue;
        }

        const QString instanceMac = extractBonjourInstanceMac(instanceName);
        if (!instanceMac.isEmpty() && !state.resolved.namesByMac.contains(instanceMac)) {
            state.resolved.namesByMac.insert(instanceMac, displayName);
        }

        const auto targetIps = state.ipsByHost.value(targetHost.toLower());
        for (const auto& ip : targetIps) {
            if (scannedIps.contains(ip)) {
                state.resolved.activeIps.insert(ip);
                if (!state.resolved.namesByIp.contains(ip)) {
                    state.resolved.namesByIp.insert(ip, displayName);
                }
            }
        }

    }
}

void parseMdnsPacketIntoState(const QByteArray& packet, const QSet<QString>& scannedIps, MdnsResolutionState& state, const QString& senderIp = QString()) {
    Q_UNUSED(senderIp)
    if (packet.size() < 12) {
        return;
    }

    int offset = 12;
    const quint16 questionCount = readDnsU16(packet, 4);
    const quint16 answerCount = readDnsU16(packet, 6);
    const quint16 authorityCount = readDnsU16(packet, 8);
    const quint16 additionalCount = readDnsU16(packet, 10);
    for (quint16 index = 0; index < questionCount; ++index) {
        decodeDnsName(packet, offset);
        offset += 4;
        if (offset > packet.size()) {
            return;
        }
    }

    const int recordCount = answerCount + authorityCount + additionalCount;
    for (int index = 0; index < recordCount; ++index) {
        const QString recordName = decodeDnsName(packet, offset);
        if (recordName.isEmpty() || offset + 10 > packet.size()) {
            return;
        }

        const quint16 type = readDnsU16(packet, offset);
        offset += 2;
        offset += 2;
        offset += 4;
        const quint16 dataLength = readDnsU16(packet, offset);
        offset += 2;
        if (offset + dataLength > packet.size()) {
            return;
        }

        const int dataOffset = offset;
        if (type == 12) {
            int nameOffset = dataOffset;
            const QString pointerName = decodeDnsName(packet, nameOffset);
            const QString reverseIp = ipFromReverseMdnsName(recordName);
            if (!reverseIp.isEmpty() && scannedIps.contains(reverseIp)) {
                const QString normalized = normalizeResolvedName(pointerName, reverseIp);
                if (!normalized.isEmpty()) {
                    state.resolved.activeIps.insert(reverseIp);
                    if (!state.resolved.namesByIp.contains(reverseIp)) {
                        state.resolved.namesByIp.insert(reverseIp, normalized);
                    }
                }
            } else {
                const QString serviceType = serviceTypeFromDnsName(recordName);
                if (!serviceType.isEmpty()) {
                    const QString key = pointerName.toLower();
                    const QString instanceName = instanceNameFromServiceName(pointerName, serviceType);
                    state.serviceByInstance.insert(key, serviceType);
                    state.instanceByFullName.insert(key, instanceName);
                }
            }
        } else if (type == 33 && dataLength >= 7) {
            int targetOffset = dataOffset + 6;
            const QString targetHost = decodeDnsName(packet, targetOffset);
            if (!targetHost.isEmpty()) {
                state.targetByInstance.insert(recordName.toLower(), targetHost);
            }
        } else if (type == 16 && dataLength > 1) {
            const QString txtName = bestNameFromTxtRecord(packet.mid(dataOffset, dataLength), QString());
            if (!txtName.isEmpty()) {
                state.nameByInstance.insert(recordName.toLower(), txtName);
            }
        } else if (type == 1 && dataLength == 4) {
            const QString ip = QStringLiteral("%1.%2.%3.%4")
                .arg(static_cast<quint8>(packet.at(dataOffset)))
                .arg(static_cast<quint8>(packet.at(dataOffset + 1)))
                .arg(static_cast<quint8>(packet.at(dataOffset + 2)))
                .arg(static_cast<quint8>(packet.at(dataOffset + 3)));
            if (scannedIps.contains(ip)) {
                state.resolved.activeIps.insert(ip);
                auto& hostIps = state.ipsByHost[recordName.toLower()];
                if (!hostIps.contains(ip)) {
                    hostIps.append(ip);
                }
            }
        }

        offset += dataLength;
    }

    materializeMdnsState(scannedIps, state);
}

BonjourResolution collectMdnsNamesWithSocket(const QSet<QString>& scannedIps,
	                                             const QStringList& serviceTypes,
	                                             const QString& adapterId,
	                                             int timeoutMs) {
    MdnsResolutionState state;
    if (scannedIps.isEmpty()) {
        return state.resolved;
    }

    QUdpSocket socket;
    const QHostAddress mdnsGroup(QStringLiteral("224.0.0.251"));
    const auto bindFlags = QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint;
    bool boundToMdnsPort = socket.bind(QHostAddress::AnyIPv4, 5353, bindFlags);
    if (!boundToMdnsPort && !socket.bind(QHostAddress::AnyIPv4, 0, bindFlags)) {
        return state.resolved;
    }

    const QNetworkInterface iface = QNetworkInterface::interfaceFromName(adapterId);
    if (iface.isValid()) {
        socket.setMulticastInterface(iface);
        if (boundToMdnsPort) {
            socket.joinMulticastGroup(mdnsGroup, iface);
        }
    } else if (boundToMdnsPort) {
        socket.joinMulticastGroup(mdnsGroup);
    }
    socket.setSocketOption(QAbstractSocket::MulticastTtlOption, 255);

    QList<QByteArray> queries;
    queries.reserve((serviceTypes.size() * 2) + qMin(scannedIps.size(), 512));
    for (const auto& serviceType : serviceTypes) {
        queries.append(buildMdnsPtrQuery(serviceType + QStringLiteral(".local")));
    }
    for (const auto& ip : sortedIpsForMdnsReverse(scannedIps, 512)) {
        const QString reverseName = reverseMdnsNameForIp(ip);
        if (!reverseName.isEmpty()) {
            queries.append(buildMdnsPtrQuery(reverseName));
        }
    }

    QList<QByteArray> directServiceQueries;
    const QStringList directServiceTypes = serviceTypes.isEmpty()
        ? priorityBonjourServiceTypes()
        : serviceTypes.mid(0, qMin(serviceTypes.size(), 12));
    directServiceQueries.reserve(directServiceTypes.size());
    for (const auto& serviceType : directServiceTypes) {
        directServiceQueries.append(buildMdnsPtrQuery(serviceType + QStringLiteral(".local")));
    }
    const QList<QString> directTargetIps = sortedIpsForMdnsReverse(scannedIps, scannedIps.size() <= 256 ? 256 : 128);

    const auto sendQueries = [&]() {
        for (int index = 0; index < queries.size(); ++index) {
            socket.writeDatagram(queries.at(index), mdnsGroup, 5353);
            if ((index + 1) % 64 == 0) {
                QThread::msleep(2);
            }
        }
    };
    const auto sendDirectQueries = [&]() {
        int sent = 0;
        for (const auto& ip : directTargetIps) {
            const QHostAddress target(ip);
            if (target.protocol() != QAbstractSocket::IPv4Protocol) {
                continue;
            }
            const QString reverseName = reverseMdnsNameForIp(ip);
            if (!reverseName.isEmpty()) {
                socket.writeDatagram(buildMdnsPtrQuery(reverseName), target, 5353);
                ++sent;
            }
            for (const auto& query : directServiceQueries) {
                socket.writeDatagram(query, target, 5353);
                ++sent;
                if (sent % 96 == 0) {
                    QThread::msleep(2);
                }
            }
        }
    };
    const auto sendFollowupQueries = [&]() {
        QList<QByteArray> followups;
        for (auto it = state.serviceByInstance.constBegin(); it != state.serviceByInstance.constEnd(); ++it) {
            const QString instanceKey = it.key();
            if (!state.queriedSrvInstances.contains(instanceKey)) {
                state.queriedSrvInstances.insert(instanceKey);
                followups.append(buildMdnsSrvQuery(instanceKey));
            }
        }
        for (auto it = state.targetByInstance.constBegin(); it != state.targetByInstance.constEnd(); ++it) {
            QString targetHost = it.value().trimmed();
            while (targetHost.endsWith(QLatin1Char('.'))) {
                targetHost.chop(1);
            }
            const QString hostKey = targetHost.toLower();
            if (!hostKey.isEmpty() && !state.queriedHosts.contains(hostKey)) {
                state.queriedHosts.insert(hostKey);
                followups.append(buildMdnsAQuery(targetHost));
            }
        }
        for (int index = 0; index < followups.size(); ++index) {
            socket.writeDatagram(followups.at(index), mdnsGroup, 5353);
            if ((index + 1) % 32 == 0) {
                QThread::msleep(1);
            }
        }
    };

    QElapsedTimer timer;
    timer.start();
    sendQueries();
    sendDirectQueries();
    bool sentRefresh = false;
    bool sentDirectRefresh = false;
    while (timer.elapsed() < timeoutMs) {
        if (!sentRefresh && timer.elapsed() > 350) {
            sendQueries();
            sentRefresh = true;
        }
        if (!sentDirectRefresh && timer.elapsed() > 900) {
            sendDirectQueries();
            sentDirectRefresh = true;
        }
        const int remaining = qMax(1, timeoutMs - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(80, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            QHostAddress sender;
            socket.readDatagram(datagram.data(), datagram.size(), &sender);
            parseMdnsPacketIntoState(datagram, scannedIps, state, sender.toString());
        }
        sendFollowupQueries();
    }
    materializeMdnsState(scannedIps, state);
    return state.resolved;
}

BonjourResolution collectBonjourNamesForService(const QSet<QString>& scannedIps, const QString& serviceType) {
    BonjourResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QString browseOutput = runTimedCommandCapture(
        QStringLiteral("dns-sd"),
        {QStringLiteral("-B"), serviceType, QStringLiteral("local")},
        1800,
        true
    );
    const QStringList instances = parseDnsSdBrowseInstances(browseOutput, serviceType);
    for (const auto& instance : instances) {
        const QString lookupOutput = runTimedCommandCapture(
            QStringLiteral("dns-sd"),
            {QStringLiteral("-L"), instance, serviceType, QStringLiteral("local")},
            1800,
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
            if (!scannedIps.contains(ip)) {
                continue;
            }
            resolved.activeIps.insert(ip);
            if (!resolved.namesByIp.contains(ip)) {
                resolved.namesByIp.insert(ip, displayName);
            }
        }
    }
    return resolved;
}

BonjourResolution collectBonjourNames(const QSet<QString>& scannedIps) {
    BonjourResolution resolved;
    if (scannedIps.isEmpty()) {
        return resolved;
    }

    const QStringList serviceTypes = allBonjourServiceTypes();

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
        for (const auto& ip : partial.activeIps) {
            resolved.activeIps.insert(ip);
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
    m_enrichmentPool.setExpiryTimeout(30000);
    m_enrichmentPool.setMaxThreadCount(enrichmentWorkerCountForProfile(QStringLiteral("balanced")));
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
        QSet<QString> recordedIps;
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
                recordedIps.insert(record.ip);
            }
        }
        {
            QMutexLocker locker(&m_liveRecordsMutex);
            for (auto liveIt = m_liveRecords.constBegin(); liveIt != m_liveRecords.constEnd(); ++liveIt) {
                ScanRecord record = liveIt.value();
                if (record.ip.trimmed().isEmpty()
                    || recordedIps.contains(record.ip)
                    || record.generation != finishedGeneration
                    || record.status == HostStatus::Offline) {
                    continue;
                }
                const QString currentGateway = cachedGateway();
                if ((record.gateway.trimmed().isEmpty()
                     || record.gateway == QStringLiteral("-")
                     || record.gateway == QStringLiteral("[n/a]"))
                    && !currentGateway.trimmed().isEmpty()) {
                    record.gateway = currentGateway;
                }
                record.mask = record.mask.trimmed().isEmpty() ? m_cachedMask : record.mask;
                record.name = routeDisplayForHost(m_activeAdapter, record);
                records.append(record);
                recordedIps.insert(record.ip);
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
        startDetailEnrichment(records, finishedGeneration, finishedProfile, true);
        startRtspEnrichment(records, finishedGeneration);
        QList<int> polishDelays;
        if (finishedProfile == QStringLiteral("fast")) {
            polishDelays = {650, 1700};
        } else if (finishedProfile == QStringLiteral("reliable")) {
            polishDelays = {900, 2400, 5200, 8800};
        } else {
            polishDelays = {750, 2200, 4600};
        }
        for (const int delayMs : polishDelays) {
            QTimer::singleShot(delayMs, this, [this, finishedGeneration, finishedProfile]() {
                if (m_cancelRequested.load() || m_activeGeneration.load() != finishedGeneration) {
                    return;
                }
                QList<ScanRecord> snapshot;
                {
                    QMutexLocker locker(&m_liveRecordsMutex);
                    snapshot = m_liveRecords.values();
                }
                if (snapshot.isEmpty()) {
                    return;
                }
                startNameEnrichment(snapshot, finishedGeneration);
                startDetailEnrichment(snapshot, finishedGeneration, finishedProfile, true);
                startRtspEnrichment(snapshot, finishedGeneration);
            });
        }
    });
}

NetworkScanService::~NetworkScanService() {
    cancel();
    m_watcher->waitForFinished();
    m_scanPool.waitForDone();
    m_enrichmentPool.waitForDone();
}

QList<AdapterInfo> NetworkScanService::adapters() const {
    QList<AdapterInfo> items;
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const auto& iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp)) {
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
    if (adapter.ip.trimmed().isEmpty()) {
        emit scanFailed(QStringLiteral("Не найден активный сетевой адаптер. Обновите адаптеры через пару секунд."));
        return;
    }
    const QString activeScanProfile = normalizedScanProfile(scanProfile);
    m_activeScanProfile = activeScanProfile;
    m_scanPool.setMaxThreadCount(workerCountForProfile(maxWorkers, activeScanProfile));
    m_enrichmentPool.setMaxThreadCount(enrichmentWorkerCountForProfile(activeScanProfile));
    emit scanStarted();
    setCachedGateway(QStringLiteral("-"));
    m_cachedMask = detectMask(adapter);
    setCachedGateway(detectGateway(adapter));
    setPrefetchedMacs({});
    {
        QMutexLocker locker(&m_nameEnrichmentMutex);
        m_nameEnrichmentInFlight.clear();
    }
    {
        QMutexLocker locker(&m_detailEnrichmentMutex);
        m_detailEnrichmentInFlight.clear();
        m_detailEnrichmentCompleted.clear();
    }
    {
        QMutexLocker locker(&m_prefetchedPingMutex);
        m_prefetchedPingDisplay.clear();
    }
    const auto startMacs = captureArpTable(adapter.id);
    if (!startMacs.isEmpty()) {
        setPrefetchedMacs(startMacs);
    }
    const auto initialKnownMacs = prefetchedMacsSnapshot();
    const QString initialGateway = cachedGateway();
    const auto scheduledIps = prioritizeIpsForScan(ips, initialKnownMacs, initialGateway, adapter.ip);
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
        ? 28
        : (activeScanProfile == QStringLiteral("reliable") ? 14 : 22);
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

    (void)QtConcurrent::run(&m_enrichmentPool, [scheduledIps, adapter, activeScanProfile]() {
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
    QTimer::singleShot(40, this, [this, scheduledIps, generation]() {
        if (!m_cancelRequested.load() && generation == m_activeGeneration.load()) {
            startBonjourEnrichment(scheduledIps, generation);
        }
    });
#endif
    QTimer::singleShot(90, this, [this, scheduledIps, generation]() {
        if (!m_cancelRequested.load() && generation == m_activeGeneration.load()) {
            startSsdpEnrichment(scheduledIps, generation);
        }
    });

    const auto launchPrioritizedProbe = [this, adapter, generation, activeScanProfile](const QString& ip, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, activeScanProfile, ip]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run(&m_enrichmentPool, [this, adapter, generation, activeScanProfile, ip]() {
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
                    publishLiveRecord(record);
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
                    if (!hasUsefulSeedSignal(seed)) {
                        return;
                    }
                    m_liveRecords.insert(seed.ip, seed);
                }
            }
            emit recordReady(seed);
            if (needsNameEnrichment(seed)) {
                startNameEnrichment({seed}, seed.generation);
            }
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
                if (needsNameEnrichment(record)) {
                    startNameEnrichment({record}, record.generation);
                }
            }
        });
    };

    const auto launchInstantProbe = [this, adapter, generation, activeScanProfile](const QString& ip, int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, activeScanProfile, ip]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run(&m_enrichmentPool, [this, adapter, generation, activeScanProfile, ip]() {
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
                    record.typeHint = detectTypeHint(openPorts, ping.success, record.onLink, record.hostName, record.vendor, record.mac);
                    record.speed = ping.success ? QStringLiteral("icmp") : QStringLiteral("tcp");
                    enriched = true;
                }

                if ((record.status != HostStatus::Offline)
                    && record.hostName.isEmpty()
                    && (ping.success || !openPorts.isEmpty())) {
                    const QString resolvedName = resolveHostNameDeep(ip, adapter.id, 900);
                    if (!resolvedName.isEmpty()) {
                        record.hostName = resolvedName;
                        record.vendor = resolvedName;
                        rememberResolvedName(record.ip, record.mac, resolvedName);
                        enriched = true;
                    }
                }

                if (!canShowInitial
                    && record.status != HostStatus::Offline
                    && (ping.success || !openPorts.isEmpty())) {
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

    (void)QtConcurrent::run(&m_enrichmentPool, [this, adapter, generation, scheduledIpSet, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
        const QString detectedGateway = detectGateway(adapter);
        const auto discoveredMacs = captureArpTable(adapter.id);
        if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
            return;
        }

        QMetaObject::invokeMethod(this, [this, adapter, generation, scheduledIpSet, detectedGateway, discoveredMacs, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            const QString gateway = normalizeGatewayIp(detectedGateway);
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

            const int probeLimit = qMin(
                discoveredSeeds.size(),
                qMax(instantProbeLimitForProfile(activeScanProfile),
                     activeScanProfile == QStringLiteral("fast")
                         ? 72
                         : (activeScanProfile == QStringLiteral("reliable") ? 48 : 60))
            );
            for (int index = 0; index < discoveredSeeds.size(); ++index) {
                launchFallbackSeed(discoveredSeeds.at(index), 20 + index * 50);
                if (index < probeLimit) {
                    launchInstantProbe(discoveredSeeds.at(index).ip, index * 18);
                }
            }
        }, Qt::QueuedConnection);
    });

    const auto launchArpHarvest = [this, adapter, generation, scheduledIpSet, launchFallbackSeed, launchInstantProbe, activeScanProfile](int delayMs) {
        QTimer::singleShot(delayMs, this, [this, adapter, generation, scheduledIpSet, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
            if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                return;
            }

            (void)QtConcurrent::run(&m_enrichmentPool, [this, adapter, generation, scheduledIpSet, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
                const auto refreshedMacs = captureArpTable(adapter.id);
                const QString refreshedGateway = detectGateway(adapter);
                if (m_cancelRequested.load()
                    || generation != m_activeGeneration.load()) {
                    return;
                }

                QMetaObject::invokeMethod(this, [this, adapter, generation, scheduledIpSet, refreshedMacs, refreshedGateway, launchFallbackSeed, launchInstantProbe, activeScanProfile]() {
                    if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                        return;
                    }

                    const QString gateway = normalizeGatewayIp(refreshedGateway);
                    if (gateway != QStringLiteral("-")) {
                        setCachedGateway(gateway);
                    }
                    mergePrefetchedMacs(refreshedMacs);

                    QSet<QString> visibleIps;
                    QList<ScanRecord> gatewayUpdates;
                    {
                        QMutexLocker locker(&m_liveRecordsMutex);
                        visibleIps.reserve(m_liveRecords.size());
                        for (auto liveIt = m_liveRecords.begin(); liveIt != m_liveRecords.end(); ++liveIt) {
                            visibleIps.insert(liveIt.key());
                            if (gateway != QStringLiteral("-")
                                && (liveIt->gateway.trimmed().isEmpty()
                                    || liveIt->gateway == QStringLiteral("-")
                                    || liveIt->gateway == QStringLiteral("[n/a]")
                                    || !isValidGatewayIp(liveIt->gateway))) {
                                ScanRecord updated = liveIt.value();
                                updated.gateway = gateway;
                                updated.name = routeDisplayForHost(adapter, updated);
                                liveIt.value() = updated;
                                gatewayUpdates.append(updated);
                            }
                        }
                    }
                    for (const auto& update : gatewayUpdates) {
                        emit recordReady(update);
                    }

                    QList<ScanRecord> seeds;
                    seeds.reserve(qMin(refreshedMacs.size(), scheduledIpSet.size()));
                    for (auto it = refreshedMacs.constBegin(); it != refreshedMacs.constEnd(); ++it) {
                        if (!scheduledIpSet.contains(it.key()) || visibleIps.contains(it.key())) {
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
                        seed.gateway = cachedGateway();
                        seed.mask = m_cachedMask;
                        seed.onLink = isOnLink(seed.ip, adapter);
                        seed.typeHint = QStringLiteral("arp");
                        seed.hostName = cachedResolvedName(seed.ip, seed.mac);
                        seed.vendor = vendorDisplayText(seed.hostName, seed.mac, m_vendorDb);
                        seed.name = routeDisplayForHost(adapter, seed);
                        seeds.append(seed);
                    }

                    std::sort(seeds.begin(), seeds.end(), [](const ScanRecord& left, const ScanRecord& right) {
                        return QHostAddress(left.ip).toIPv4Address() < QHostAddress(right.ip).toIPv4Address();
                    });

                    const int probeLimit = qMin(
                        seeds.size(),
                        activeScanProfile == QStringLiteral("fast")
                            ? 80
                            : (activeScanProfile == QStringLiteral("reliable") ? 56 : 68)
                    );
                    for (int index = 0; index < seeds.size(); ++index) {
                        launchFallbackSeed(seeds.at(index), index * 35);
                        if (index < probeLimit) {
                            launchInstantProbe(seeds.at(index).ip, index * 24);
                        }
                    }
                }, Qt::QueuedConnection);
            });
        });
    };

    launchArpHarvest(activeScanProfile == QStringLiteral("fast") ? 900 : (activeScanProfile == QStringLiteral("reliable") ? 1700 : 1250));
    launchArpHarvest(activeScanProfile == QStringLiteral("fast") ? 2300 : (activeScanProfile == QStringLiteral("reliable") ? 3900 : 3000));
    launchArpHarvest(activeScanProfile == QStringLiteral("fast") ? 4200 : (activeScanProfile == QStringLiteral("reliable") ? 6800 : 5200));

    const QSet<QString> immediateProbeSet(immediateProbeIps.constBegin(), immediateProbeIps.constEnd());
    (void)QtConcurrent::run(&m_enrichmentPool, [this, adapter, generation, startIp, endIp, scheduledIps, immediateProbeSet, launchPrioritizedProbe, launchPingSeed, activeScanProfile, earlyProbeLimit]() {
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
                publishLiveRecord(record);
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
    m_enrichmentPool.clear();
    {
        QMutexLocker locker(&m_liveRecordsMutex);
        m_liveRecords.clear();
    }
    {
        QMutexLocker locker(&m_nameEnrichmentMutex);
        m_nameEnrichmentInFlight.clear();
    }
    {
        QMutexLocker locker(&m_detailEnrichmentMutex);
        m_detailEnrichmentInFlight.clear();
        m_detailEnrichmentCompleted.clear();
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
    const QString adapterId = m_activeAdapter.id;
    const auto publishResolution = [guard, generation](const BonjourResolution& bonjourNames) {
        if (!guard || isEmptyBonjourResolution(bonjourNames)) {
            return;
        }
        QMetaObject::invokeMethod(guard.data(), [guard, generation, bonjourNames]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
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
                const QString ip = it.key();
                const QString resolvedName = normalizeResolvedName(it.value(), ip);
                if (resolvedName.isEmpty()) {
                    continue;
                }
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(ip);
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        updated = liveIt.value();
                        recordMac = updated.mac;
                        updated.hostName = resolvedName;
                        updated.vendor = resolvedName;
                        guard->m_liveRecords.insert(ip, updated);
                        shouldEmit = true;
                    }
                }
                if (!shouldEmit) {
                    continue;
                }
                rememberResolvedName(ip, recordMac, resolvedName);
                emit guard->recordReady(updated);
                if (updated.speed == QStringLiteral("mdns")
                    || isMissingPingDisplay(updated.pingDisplay)
                    || updated.portsDisplay == QStringLiteral("-")
                    || updated.port == QStringLiteral("-")) {
                    QPointer<NetworkScanService> probeGuard = guard;
                    const QString probeIp = ip;
                    if (!probeGuard) {
                        continue;
                    }
                    (void)QtConcurrent::run(&probeGuard->m_enrichmentPool, [probeGuard, generation, probeIp]() {
                        if (!probeGuard
                            || probeGuard->m_cancelRequested.load()
                            || probeGuard->m_activeGeneration.load() != generation) {
                            return;
                        }
                        auto record = probeGuard->probeHost(probeIp, probeGuard->m_activeAdapter, probeGuard->m_activeScanProfile);
                        if (!probeGuard
                            || probeGuard->m_cancelRequested.load()
                            || record.ip.isEmpty()
                            || record.status == HostStatus::Offline
                            || record.generation != probeGuard->m_activeGeneration.load()) {
                            return;
                        }
                        QMetaObject::invokeMethod(probeGuard.data(), [probeGuard, record]() mutable {
                            if (probeGuard) {
                                probeGuard->publishLiveRecord(record);
                            }
                        }, Qt::QueuedConnection);
                    });
                }
            }
        }, Qt::QueuedConnection);
    };

    (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        const auto quickNames = collectMdnsNamesWithSocket(scannedIps, priorityBonjourServiceTypes(), adapterId, 1450);
        if (!isEmptyBonjourResolution(quickNames)) {
            publishResolution(quickNames);
        }
    });

    QTimer::singleShot(1450, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto broadNames = collectMdnsNamesWithSocket(scannedIps, allBonjourServiceTypes(), adapterId, 2300);
            if (!isEmptyBonjourResolution(broadNames)) {
                publishResolution(broadNames);
            }
        });
    });

    QTimer::singleShot(3500, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto lateNames = collectMdnsNamesWithSocket(scannedIps, allBonjourServiceTypes(), adapterId, 2600);
            if (!isEmptyBonjourResolution(lateNames)) {
                publishResolution(lateNames);
            }
        });
    });

    QTimer::singleShot(6200, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto settledNames = collectMdnsNamesWithSocket(scannedIps, allBonjourServiceTypes(), adapterId, 2600);
            if (!isEmptyBonjourResolution(settledNames)) {
                publishResolution(settledNames);
            }
        });
    });

    const auto launchService = [guard, generation, scannedIps, publishResolution](const QString& serviceType, int delayMs) {
        if (!guard) {
            return;
        }
        QTimer::singleShot(delayMs, guard.data(), [guard, generation, scannedIps, serviceType, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, serviceType, publishResolution]() {
                if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                    return;
                }
                const auto partial = collectBonjourNamesForService(scannedIps, serviceType);
                if (isEmptyBonjourResolution(partial)) {
                    return;
                }
                publishResolution(partial);
            });
        });
    };

    int delayMs = 0;
    for (const auto& serviceType : priorityBonjourServiceTypes()) {
        launchService(serviceType, delayMs);
        delayMs += 35;
    }

    delayMs = 1250;
    for (const auto& serviceType : priorityBonjourServiceTypes()) {
        launchService(serviceType, delayMs);
        delayMs += 50;
    }

    delayMs = 2300;
    for (const auto& serviceType : allBonjourServiceTypes()) {
        launchService(serviceType, delayMs);
        delayMs += 55;
    }
#endif
}

void NetworkScanService::startSsdpEnrichment(const QList<QString>& ips, quint64 generation) {
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
    const QString adapterId = m_activeAdapter.id;
    const auto publishResolution = [guard, generation](const SsdpResolution& ssdp) {
        if (!guard || isEmptySsdpResolution(ssdp)) {
            return;
        }

        QMetaObject::invokeMethod(guard.data(), [guard, generation, ssdp]() {
            if (!guard || guard->m_activeGeneration.load() != generation) {
                return;
            }

            QList<ScanRecord> updates;
            updates.reserve(ssdp.activeIps.size());
            for (const auto& ip : ssdp.activeIps) {
                ScanRecord record;
                const QString discoveredName = normalizeResolvedName(ssdp.namesByIp.value(ip), ip);
                const QString discoveredType = ssdp.typesByIp.value(ip, QStringLiteral("upnp")).trimmed();
                const QString discoveredWeb = ssdp.webByIp.value(ip).trimmed();
                const QString discoveredPort = ssdp.portsByIp.value(ip).trimmed();
                bool existed = false;
                {
                    QMutexLocker locker(&guard->m_liveRecordsMutex);
                    const auto liveIt = guard->m_liveRecords.constFind(ip);
                    if (liveIt != guard->m_liveRecords.constEnd()) {
                        record = liveIt.value();
                        existed = true;
                    } else {
                        record.ip = ip;
                        record.generation = generation;
                        record.status = HostStatus::Unknown;
                        record.pingDisplay = QStringLiteral("[n/a]");
                        record.portsDisplay = QStringLiteral("-");
                        record.port = QStringLiteral("-");
                        record.webDetect = QStringLiteral("[n/a]");
                        record.speed = QStringLiteral("ssdp");
                        record.typeHint = discoveredType.isEmpty() ? QStringLiteral("upnp") : discoveredType;
                        record.mac = guard->prefetchedMacForIp(ip);
                        record.gateway = guard->cachedGateway();
                        record.mask = guard->m_cachedMask;
                        record.onLink = isOnLink(ip, guard->m_activeAdapter);
                        record.hostName = discoveredName;
                        record.vendor = vendorDisplayText(record.hostName, record.mac, guard->m_vendorDb);
                        record.name = routeDisplayForHost(guard->m_activeAdapter, record);
                    }
                }

                bool changed = false;
                if (!discoveredName.isEmpty()
                    && (isUnknownVendorLabel(record.hostName) || record.hostName == record.vendor)) {
                    record.hostName = discoveredName;
                    record.vendor = discoveredName;
                    changed = true;
                } else if (isUnknownVendorLabel(record.vendor)) {
                    const QString vendor = vendorDisplayText(record.hostName, record.mac, guard->m_vendorDb);
                    if (!isUnknownVendorLabel(vendor)) {
                        record.vendor = vendor;
                        changed = true;
                    }
                }

                if (!discoveredWeb.isEmpty() && isUnknownVendorLabel(record.webDetect)) {
                    record.webDetect = discoveredWeb;
                    changed = true;
                }
                if (!discoveredPort.isEmpty()) {
                    const QString mergedPorts = mergePortDisplay(record.port, discoveredPort);
                    if (record.port != mergedPorts || record.portsDisplay != mergedPorts) {
                        record.port = mergedPorts;
                        record.portsDisplay = mergedPorts;
                        changed = true;
                    }
                }
                const bool weakCurrentType = isUnknownVendorLabel(record.typeHint)
                    || record.typeHint == QStringLiteral("icmp")
                    || record.typeHint == QStringLiteral("udp")
                    || record.typeHint == QStringLiteral("mdns")
                    || record.typeHint == QStringLiteral("arp");
                if (!discoveredType.isEmpty() && weakCurrentType) {
                    record.typeHint = discoveredType;
                    changed = true;
                }
                if (record.speed.trimmed().isEmpty() || record.speed == QStringLiteral("[n/a]")) {
                    record.speed = QStringLiteral("ssdp");
                    changed = true;
                }
                const QString routeName = routeDisplayForHost(guard->m_activeAdapter, record);
                if (record.name != routeName) {
                    record.name = routeName;
                    changed = true;
                }

                if (changed || !existed) {
                    updates.append(record);
                }
            }

            for (auto record : updates) {
                if (!record.hostName.trimmed().isEmpty() && !isUnknownVendorLabel(record.hostName)) {
                    rememberResolvedName(record.ip, record.mac, record.hostName);
                }
                guard->publishLiveRecord(record);
                if (isMissingPingDisplay(record.pingDisplay) || record.port == QStringLiteral("-") || record.portsDisplay == QStringLiteral("-")) {
                    QPointer<NetworkScanService> probeGuard = guard;
                    const QString probeIp = record.ip;
                    if (!probeGuard) {
                        continue;
                    }
                    (void)QtConcurrent::run(&probeGuard->m_enrichmentPool, [probeGuard, generation, probeIp]() {
                        if (!probeGuard
                            || probeGuard->m_cancelRequested.load()
                            || probeGuard->m_activeGeneration.load() != generation) {
                            return;
                        }
                        auto probed = probeGuard->probeHost(probeIp, probeGuard->m_activeAdapter, probeGuard->m_activeScanProfile);
                        if (!probeGuard
                            || probeGuard->m_cancelRequested.load()
                            || probed.ip.isEmpty()
                            || probed.status == HostStatus::Offline
                            || probed.generation != probeGuard->m_activeGeneration.load()) {
                            return;
                        }
                        QMetaObject::invokeMethod(probeGuard.data(), [probeGuard, probed]() mutable {
                            if (probeGuard) {
                                probeGuard->publishLiveRecord(probed);
                            }
                        }, Qt::QueuedConnection);
                    });
                }
            }
        }, Qt::QueuedConnection);
    };

    (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        const auto ssdp = collectSsdpDevices(scannedIps, adapterId, 1500);
        if (!isEmptySsdpResolution(ssdp)) {
            publishResolution(ssdp);
        }
    });

    (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        const auto wsd = collectWsDiscoveryDevices(scannedIps, adapterId, 1500);
        if (!isEmptySsdpResolution(wsd)) {
            publishResolution(wsd);
        }
    });

    QTimer::singleShot(450, this, [guard, generation, scannedIps, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto mobile = collectLibimobiledeviceNames(scannedIps, guard->prefetchedMacsSnapshot());
            if (!isEmptySsdpResolution(mobile)) {
                publishResolution(mobile);
            }
        });
    });

    QTimer::singleShot(900, this, [guard, generation, scannedIps, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto hints = collectRouterDhcpHints(scannedIps, guard->cachedGateway(), 1900);
            if (!isEmptySsdpResolution(hints)) {
                publishResolution(hints);
            }
        });
    });

    QTimer::singleShot(2600, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            SsdpResolution combined = collectSsdpDevices(scannedIps, adapterId, 1800);
            mergeDeviceResolution(combined, collectWsDiscoveryDevices(scannedIps, adapterId, 1700));
            if (!isEmptySsdpResolution(combined)) {
                publishResolution(combined);
            }
        });
    });

    QTimer::singleShot(5200, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            SsdpResolution combined = collectSsdpDevices(scannedIps, adapterId, 2200);
            mergeDeviceResolution(combined, collectWsDiscoveryDevices(scannedIps, adapterId, 1900));
            mergeDeviceResolution(combined, collectRouterDhcpHints(scannedIps, guard->cachedGateway(), 2200));
            if (!isEmptySsdpResolution(combined)) {
                publishResolution(combined);
            }
        });
    });
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
    (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, candidates]() {
        QList<ScanRecord> updates;
        updates.reserve(candidates.size());

        for (const auto& record : candidates) {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
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
    for (auto candidate : candidates) {
        (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, candidate]() mutable {
            if (!guard) {
                return;
            }
            QString name;
            if (guard->m_activeGeneration.load() == generation && !guard->m_cancelRequested.load()) {
                name = cachedResolvedName(candidate.ip, candidate.mac);
                if (name.isEmpty()) {
                    name = resolveHostNameDeep(candidate.ip, guard->m_activeAdapter.id, 1300);
                }
                if (!name.isEmpty()) {
                    rememberResolvedName(candidate.ip, candidate.mac, name);
                }
            }

            QMetaObject::invokeMethod(guard.data(), [guard, generation, candidate, name]() mutable {
                if (!guard) {
                    return;
                }
                {
                    QMutexLocker locker(&guard->m_nameEnrichmentMutex);
                    guard->m_nameEnrichmentInFlight.remove(candidate.ip);
                }
                if (guard->m_activeGeneration.load() != generation || name.isEmpty()) {
                    return;
                }

                ScanRecord updated = candidate;
                updated.hostName = name;
                updated.vendor = name;

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
            }, Qt::QueuedConnection);
        });
    }
}

void NetworkScanService::startDetailEnrichment(const QList<ScanRecord>& records, quint64 generation, const QString& scanProfile, bool force) {
    QList<ScanRecord> candidates;
    candidates.reserve(records.size());
    {
        QMutexLocker locker(&m_detailEnrichmentMutex);
        for (const auto& record : records) {
            if (!needsDetailEnrichment(record)
                || m_detailEnrichmentInFlight.contains(record.ip)
                || (!force && m_detailEnrichmentCompleted.contains(record.ip))) {
                continue;
            }
            m_detailEnrichmentInFlight.insert(record.ip);
            candidates.append(record);
        }
    }
    if (candidates.isEmpty()) {
        return;
    }

    QPointer<NetworkScanService> guard(this);
    const AdapterInfo adapter = m_activeAdapter;
    for (auto candidate : candidates) {
        (void)QtConcurrent::run(&m_enrichmentPool, [guard, generation, candidate, scanProfile, adapter]() mutable {
            if (!guard) {
                return;
            }

            auto record = candidate;
            bool changed = false;
            const ScanTiming timing = scanTimingForProfile(scanProfile);
            const int polishPortTimeoutMs = qBound(220, timing.portTimeoutMs + 140, 750);
            if (guard->m_activeGeneration.load() != generation || guard->m_cancelRequested.load()) {
                QMetaObject::invokeMethod(guard.data(), [guard, generation, ip = record.ip]() {
                    if (!guard) {
                        return;
                    }
                    QMutexLocker locker(&guard->m_detailEnrichmentMutex);
                    guard->m_detailEnrichmentInFlight.remove(ip);
                    if (guard->m_activeGeneration.load() == generation) {
                        guard->m_detailEnrichmentCompleted.insert(ip);
                    }
                }, Qt::QueuedConnection);
                return;
            }

            QString gateway = guard->cachedGateway();
            if (!isValidGatewayIp(gateway)) {
                gateway = detectGateway(adapter);
                if (isValidGatewayIp(gateway)) {
                    guard->setCachedGateway(gateway);
                }
            }
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

            if (isMissingPingDisplay(record.pingDisplay)) {
                PingResult ping = NetworkScanService::pingHost(record.ip, adapter.ip, qBound(320, timing.pingTimeoutMs, 1400));
                if (!ping.success && (record.onLink || (!record.mac.trimmed().isEmpty() && record.mac != QStringLiteral("-")))) {
                    ping = NetworkScanService::retryPingHost(
                        record.ip,
                        adapter.ip,
                        qBound(320, timing.pingTimeoutMs, 1400),
                        qBound(900, timing.retryWindowMs / 2, 2800),
                        qBound(120, timing.retryIntervalMs, 420)
                    );
                }
                if (ping.success) {
                    record.status = HostStatus::Online;
                    record.pingDisplay = ping.display.isEmpty() ? QStringLiteral("online") : ping.display;
                    record.speed = QStringLiteral("icmp");
                    changed = true;
                    if (record.hostName.isEmpty() || isUnknownVendorLabel(record.hostName)) {
                        QString name = ping.resolvedName;
                        if (name.isEmpty()) {
                            name = cachedResolvedName(record.ip, record.mac);
                        }
                        if (!name.isEmpty()) {
                            record.hostName = name;
                            record.vendor = name;
                            rememberResolvedName(record.ip, record.mac, name);
                            changed = true;
                        }
                    }
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
                const QString typeHint = detectTypeHint(openPorts, pingSuccess, record.onLink, record.hostName, record.vendor, record.mac);
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
            } else if (isUnknownVendorLabel(record.typeHint)) {
                const bool pingSuccess = !isMissingPingDisplay(record.pingDisplay);
                const QString typeHint = detectTypeHint({}, pingSuccess, record.onLink, record.hostName, record.vendor, record.mac);
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
            }

            if (isUnknownVendorLabel(record.hostName)) {
                QString name = cachedResolvedName(record.ip, record.mac);
                if (name.isEmpty()) {
                    name = resolveHostNameDeep(record.ip, adapter.id, 1400);
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

            QMetaObject::invokeMethod(guard.data(), [guard, generation, record, changed]() mutable {
                if (!guard) {
                    return;
                }
                {
                    QMutexLocker locker(&guard->m_detailEnrichmentMutex);
                    guard->m_detailEnrichmentInFlight.remove(record.ip);
                    if (guard->m_activeGeneration.load() == generation) {
                        guard->m_detailEnrichmentCompleted.insert(record.ip);
                    }
                }
                if (changed && guard->m_activeGeneration.load() == generation) {
                    guard->publishLiveRecord(record);
                }
            }, Qt::QueuedConnection);
        });
    }
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

    if (needsNameEnrichment(record)) {
        startNameEnrichment({record}, record.generation);
    }
    if (needsDetailEnrichment(record)) {
        startDetailEnrichment({record}, record.generation, m_activeScanProfile, false);
    }
}

QString NetworkScanService::cachedGateway() const {
    QMutexLocker locker(&m_routeMutex);
    return m_cachedGateway;
}

void NetworkScanService::setCachedGateway(const QString& gateway) {
    const QString normalized = normalizeGatewayIp(gateway);
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
            resolvedName = resolveHostNameDeep(ip, adapter.id, timing.pingTimeoutMs);
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
            resolvedName = resolveHostNameDeep(ip, adapter.id, timing.pingTimeoutMs);
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
                resolvedName = resolveHostNameDeep(ip, adapter.id, timing.pingTimeoutMs);
            }
        }
    }

    if (ping.success) {
        row.status = HostStatus::Online;
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
        || !openPorts.isEmpty();
    if (resolvedName.isEmpty() && hasReachabilitySignal) {
        resolvedName = resolveHostNameDeep(ip, adapter.id, timing.pingTimeoutMs);
    }

    QString bestResolvedName = resolvedName;
    if (bestResolvedName.isEmpty()) {
        bestResolvedName = cachedResolvedName(row.ip, row.mac);
    }
    if (bestResolvedName.isEmpty() && containsValueInsensitive(openPorts, QStringLiteral("62078"))) {
        bestResolvedName = resolveAppleLockdownName(row.ip, qMin(850, timing.pingTimeoutMs + 220));
    }
    if (!bestResolvedName.isEmpty()) {
        rememberResolvedName(row.ip, row.mac, bestResolvedName);
    }
    row.hostName = bestResolvedName;
    row.vendor = vendorDisplayText(bestResolvedName, row.mac, m_vendorDb);
    row.name = routeDisplayForHost(adapter, row);
    row.webDetect = detectWebService(ip, openPorts);
    row.typeHint = detectTypeHint(openPorts, ping.success, row.onLink, row.hostName, row.vendor, row.mac);
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

    static const QRegularExpression summaryRe(QStringLiteral("=\\s*[0-9]+(?:[\\.,][0-9]+)?/([0-9]+(?:[\\.,][0-9]+)?)/[0-9]+(?:[\\.,][0-9]+)?/[0-9]+(?:[\\.,][0-9]+)?\\s*(?:ms|мс)"),
                                              QRegularExpression::CaseInsensitiveOption);
    const auto summaryMatch = summaryRe.match(output);
    if (summaryMatch.hasMatch()) {
        QString value = summaryMatch.captured(1);
        value.replace(QLatin1Char(','), QLatin1Char('.'));
        result.success = true;
        result.display = QStringLiteral("%1 ms").arg(qMax(1, qRound(value.toDouble())));
        return result;
    }

    static const QRegularExpression averageRe(QStringLiteral("(?:Average|avg|Среднее)\\s*=\\s*([0-9]+(?:[\\.,][0-9]+)?)\\s*(?:ms|мс)?"),
                                              QRegularExpression::CaseInsensitiveOption);
    const auto averageMatch = averageRe.match(output);
    if (averageMatch.hasMatch()) {
        QString value = averageMatch.captured(1);
        value.replace(QLatin1Char(','), QLatin1Char('.'));
        result.success = true;
        result.display = QStringLiteral("%1 ms").arg(qMax(1, qRound(value.toDouble())));
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
    if (containsValueInsensitive(openPorts, QStringLiteral("9443"))) {
        endpoints.append(QStringLiteral("https://%1:9443").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("5001"))) {
        endpoints.append(QStringLiteral("https://%1:5001").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("80"))) {
        endpoints.append(QStringLiteral("http://%1").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8080"))) {
        endpoints.append(QStringLiteral("http://%1:8080").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8081"))) {
        endpoints.append(QStringLiteral("http://%1:8081").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8090"))) {
        endpoints.append(QStringLiteral("http://%1:8090").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("5000"))) {
        endpoints.append(QStringLiteral("http://%1:5000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("7000"))) {
        endpoints.append(QStringLiteral("http://%1:7000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8000"))) {
        endpoints.append(QStringLiteral("http://%1:8000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8008"))) {
        endpoints.append(QStringLiteral("http://%1:8008").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8060"))) {
        endpoints.append(QStringLiteral("http://%1:8060").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8888"))) {
        endpoints.append(QStringLiteral("http://%1:8888").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("9000"))) {
        endpoints.append(QStringLiteral("http://%1:9000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("9090"))) {
        endpoints.append(QStringLiteral("http://%1:9090").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("10000"))) {
        endpoints.append(QStringLiteral("http://%1:10000").arg(ip));
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
        const QString mac = normalizeMacString(match.captured(3));
        if (mac != QStringLiteral("-")) {
            entries.insert(ip, mac);
        }
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
        const QString mac = normalizeMacString(macToken);
        if (mac != QStringLiteral("-")) {
            entries.insert(ip, mac);
        }
    }
    for (auto it = entries.constBegin(); it != entries.constEnd(); ++it) {
        const QString ip = it.key();
        const QString mac = it.value();
        if (ip.startsWith(QStringLiteral("169.254.")) && mac != QStringLiteral("-")) {
            const QString name = reverseLookupName(ip);
            if (!name.isEmpty()) {
                rememberResolvedName(ip, mac, name);
            }
        }
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
        const QString mac = normalizeMacString(match.captured(2));
        if (mac != QStringLiteral("-")) {
            entries.insert(match.captured(1), mac);
        }
    }
#endif
    return entries;
}

QString NetworkScanService::resolveName(const QString& ip) {
    const QString reverseName = resolveHostNameDeep(ip, QString(), 1200);
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
    const QString cacheKey = adapter.id + QLatin1Char('|') + adapter.ip + QLatin1Char('|') + adapter.network;
    {
        QMutexLocker locker(&mutex);
        const auto cached = cache.constFind(cacheKey);
        if (cached != cache.constEnd() && isValidGatewayIp(cached.value())) {
            return cached.value();
        }
    }

    int exitStatus = -1;
    const QString output = runCommandCapture(QStringLiteral("netstat"), {QStringLiteral("-rn"), QStringLiteral("-f"), QStringLiteral("inet")}, false, &exitStatus);

    QHash<QString, QString> discovered;
    if (exitStatus >= 0) {
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
            const QString gateway = normalizeGatewayIp(parts.at(1));
            const QString netif = parts.at(3).trimmed();
            if (netif.isEmpty() || gateway == QStringLiteral("-")) {
                continue;
            }

            const bool prefer = destination == QStringLiteral("default");
            if (prefer || !discovered.contains(netif)) {
                discovered.insert(netif, gateway);
            }
        }
    }

    {
        QMutexLocker locker(&mutex);
        const QString fromNetstat = discovered.value(adapter.id, QStringLiteral("-"));
        if (isValidGatewayIp(fromNetstat)) {
            cache.insert(cacheKey, fromNetstat);
            return fromNetstat;
        }
    }

    int routeExitStatus = -1;
    const QString routeOutput = runCommandCapture(QStringLiteral("route"), {QStringLiteral("-n"), QStringLiteral("get"), QStringLiteral("default")}, false, &routeExitStatus);
    if (routeExitStatus >= 0) {
        static const QRegularExpression gatewayRe(QStringLiteral("^\\s*gateway:\\s*(\\S+)"), QRegularExpression::MultilineOption);
        static const QRegularExpression interfaceRe(QStringLiteral("^\\s*interface:\\s*(\\S+)"), QRegularExpression::MultilineOption);
        const auto gatewayMatch = gatewayRe.match(routeOutput);
        const auto interfaceMatch = interfaceRe.match(routeOutput);
        const QString routeGateway = gatewayMatch.hasMatch() ? normalizeGatewayIp(gatewayMatch.captured(1)) : QStringLiteral("-");
        const QString routeInterface = interfaceMatch.hasMatch() ? interfaceMatch.captured(1).trimmed() : QString();
        if (routeGateway != QStringLiteral("-") && (routeInterface.isEmpty() || routeInterface == adapter.id)) {
            QMutexLocker locker(&mutex);
            cache.insert(cacheKey, routeGateway);
            return routeGateway;
        }
    }
    return QStringLiteral("-");
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
