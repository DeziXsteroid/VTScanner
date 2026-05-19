#include "network/NetworkScanService.h"

#include "core/AppPaths.h"
#include "core/VendorDbService.h"

#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
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
#include <QTcpSocket>
#include <QUdpSocket>
#include <QUrl>
#include <QtConcurrent>

#include <algorithm>
#include <array>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
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
#ifdef Q_OS_WIN
    const QString windowsDir = qEnvironmentVariable("WINDIR", QStringLiteral("C:\\Windows"));
    const auto system32Tool = [&](const QString& name) {
        const QString path = QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\") + name);
        return QFileInfo::exists(path) ? path : QString();
    };
    const auto openSshTool = [&](const QString& name) {
        const QString path = QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\OpenSSH\\") + name);
        return QFileInfo::exists(path) ? path : QString();
    };

    if (program == QStringLiteral("ping")) {
        const QString path = system32Tool(QStringLiteral("ping.exe"));
        if (!path.isEmpty()) return path;
    }
    if (program == QStringLiteral("arp")) {
        const QString path = system32Tool(QStringLiteral("arp.exe"));
        if (!path.isEmpty()) return path;
    }
    if (program == QStringLiteral("route")) {
        const QString path = system32Tool(QStringLiteral("route.exe"));
        if (!path.isEmpty()) return path;
    }
    if (program == QStringLiteral("nslookup")) {
        const QString path = system32Tool(QStringLiteral("nslookup.exe"));
        if (!path.isEmpty()) return path;
    }
    if (program == QStringLiteral("netstat")) {
        const QString path = system32Tool(QStringLiteral("netstat.exe"));
        if (!path.isEmpty()) return path;
    }
    if (program == QStringLiteral("powershell")) {
        const QString path = QDir::toNativeSeparators(windowsDir + QStringLiteral("\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
        if (QFileInfo::exists(path)) return path;
    }
    if (program == QStringLiteral("ssh")) {
        const QString discovered = QStandardPaths::findExecutable(QStringLiteral("ssh"));
        if (!discovered.isEmpty()) return discovered;
        const QString path = openSshTool(QStringLiteral("ssh.exe"));
        if (!path.isEmpty()) return path;
    }
#elif defined(Q_OS_MACOS)
    if (program == QStringLiteral("ping")) return QStringLiteral("/sbin/ping");
    if (program == QStringLiteral("arp")) return QStringLiteral("/usr/sbin/arp");
    if (program == QStringLiteral("netstat")) return QStringLiteral("/usr/sbin/netstat");
    if (program == QStringLiteral("route")) return QStringLiteral("/sbin/route");
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

bool isUsableNeighborState(const QString& state) {
    const QString normalized = state.trimmed().toLower();
    return normalized == QStringLiteral("reachable")
        || normalized == QStringLiteral("stale")
        || normalized == QStringLiteral("delay")
        || normalized == QStringLiteral("probe")
        || normalized == QStringLiteral("permanent")
        || normalized == QStringLiteral("dynamic");
}

QHash<QString, QString> captureWindowsNeighborTable() {
    QHash<QString, QString> entries;
#ifdef Q_OS_WIN
    const QString script = QStringLiteral(
        "Get-NetNeighbor -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and @('Reachable','Stale','Delay','Probe','Permanent') -contains $_.State.ToString() } | "
        "ForEach-Object { \"$($_.IPAddress),$($_.LinkLayerAddress),$($_.State)\" }"
    );
    const QString output = runTimedCommandCapture(
        QStringLiteral("powershell"),
        {
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            script,
        },
        1800,
        true
    );

    for (const QString& rawLine : output.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QStringList parts = rawLine.trimmed().split(QLatin1Char(','));
        if (parts.size() < 3 || !isUsableNeighborState(parts.at(2))) {
            continue;
        }
        const QString ip = parts.at(0).trimmed();
        const QString mac = normalizeMacString(parts.at(1));
        if (QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol && mac != QStringLiteral("-")) {
            entries.insert(ip, mac);
        }
    }
#endif
    return entries;
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

bool isWeakTypeHint(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return isUnknownVendorLabel(normalized)
        || normalized == QStringLiteral("icmp")
        || normalized == QStringLiteral("udp")
        || normalized == QStringLiteral("arp")
        || normalized == QStringLiteral("mdns")
        || normalized == QStringLiteral("ssdp")
        || normalized == QStringLiteral("link");
}

bool isMissingPingDisplay(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized.isEmpty()
        || normalized == QStringLiteral("-")
        || normalized == QStringLiteral("[n/a]")
        || normalized == QStringLiteral("?");
}

QString linkPingDisplay() {
    return QStringLiteral("link");
}

bool isLinkPingDisplay(const QString& value) {
    const QString normalized = value.trimmed().toLower();
    return normalized == QStringLiteral("link") || normalized == QStringLiteral("online");
}

bool isMeasuredPingDisplay(const QString& value) {
    static const QRegularExpression pingRe(QStringLiteral(R"(\b\d+(?:[.,]\d+)?\s*ms\b)"), QRegularExpression::CaseInsensitiveOption);
    return pingRe.match(value.trimmed()).hasMatch();
}

int pingMsValue(const QString& value) {
    static const QRegularExpression pingRe(QStringLiteral(R"(\b(\d+(?:[.,]\d+)?)\s*ms\b)"), QRegularExpression::CaseInsensitiveOption);
    const auto match = pingRe.match(value.trimmed());
    if (!match.hasMatch()) {
        return -1;
    }
    QString number = match.captured(1);
    number.replace(QLatin1Char(','), QLatin1Char('.'));
    return qMax(1, qRound(number.toDouble()));
}

bool canImprovePingDisplay(const QString& current, const QString& candidate) {
    if (isMissingPingDisplay(candidate) || !isMeasuredPingDisplay(candidate)) {
        return false;
    }
    return isMissingPingDisplay(current) || isLinkPingDisplay(current);
}

bool isAppleTypeHint(const QString& value) {
    return value.trimmed().compare(QStringLiteral("apple"), Qt::CaseInsensitive) == 0;
}

bool isAppleIdentity(const QString& name, const QString& vendor, const QString& typeHint) {
    const QString blob = QStringList{name, vendor, typeHint}.join(QLatin1Char(' ')).toLower();
    return blob.contains(QStringLiteral("apple"))
        || blob.contains(QStringLiteral("iphone"))
        || blob.contains(QStringLiteral("ipad"))
        || blob.contains(QStringLiteral("macbook"))
        || blob.contains(QStringLiteral("imac"))
        || blob.contains(QStringLiteral("airplay"))
        || blob.contains(QStringLiteral("companion-link"));
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

    if (canImprovePingDisplay(target.pingDisplay, source.pingDisplay)) {
        target.pingDisplay = source.pingDisplay;
        if (source.status == HostStatus::Online) {
            target.status = HostStatus::Online;
        }
        if (isUnknownVendorLabel(target.speed) && !isUnknownVendorLabel(source.speed)) {
            target.speed = source.speed;
        }
        if (isWeakTypeHint(target.typeHint) && !isWeakTypeHint(source.typeHint)) {
            target.typeHint = source.typeHint;
        }
    } else if (isMeasuredPingDisplay(target.pingDisplay) && isMeasuredPingDisplay(source.pingDisplay)) {
        const int targetPingMs = pingMsValue(target.pingDisplay);
        const int sourcePingMs = pingMsValue(source.pingDisplay);
        if (sourcePingMs > 0 && (targetPingMs < 0 || sourcePingMs <= targetPingMs)) {
            target.pingDisplay = source.pingDisplay;
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
    if (isWeakTypeHint(target.typeHint) && !isWeakTypeHint(source.typeHint)) {
        target.typeHint = source.typeHint;
    }

    if (isUnknownVendorLabel(target.hostName) && !isUnknownVendorLabel(source.hostName)) {
        target.hostName = source.hostName;
    }
    if (isAppleTypeHint(source.typeHint) && isUnknownVendorLabel(target.vendor)) {
        target.vendor = QStringLiteral("Apple, Inc.");
    }
    if (!isUnknownVendorLabel(target.hostName) && !isAppleIdentity(target.hostName, target.vendor, target.typeHint)) {
        target.vendor = target.hostName;
    } else if (isUnknownVendorLabel(target.vendor) && !isUnknownVendorLabel(source.vendor)) {
        target.vendor = source.vendor;
    }
    if (isAppleIdentity(target.hostName, target.vendor, target.typeHint) && isUnknownVendorLabel(target.vendor)) {
        target.vendor = QStringLiteral("Apple, Inc.");
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
        || !isUnknownVendorLabel(record.webDetect)
        || (record.onLink
            && !record.mac.trimmed().isEmpty()
            && record.mac != QStringLiteral("-"));
}

bool hasUsableMac(const QString& mac) {
    const QString normalized = normalizeMacString(mac);
    return !normalized.isEmpty() && normalized != QStringLiteral("-");
}

bool isAdapterAddress(const QString& ip, const AdapterInfo& adapter) {
    return QHostAddress(ip).toIPv4Address() == QHostAddress(adapter.ip).toIPv4Address();
}

QString adapterHardwareMac(const AdapterInfo& adapter) {
    for (const auto& iface : QNetworkInterface::allInterfaces()) {
        bool matches = iface.name() == adapter.id
            || iface.humanReadableName() == adapter.name;
        if (!matches) {
            for (const auto& entry : iface.addressEntries()) {
                if (entry.ip().toString() == adapter.ip) {
                    matches = true;
                    break;
                }
            }
        }
        if (!matches) {
            continue;
        }
        const QString mac = normalizeMacString(iface.hardwareAddress());
        if (mac != QStringLiteral("-")) {
            return mac;
        }
    }
    return QStringLiteral("-");
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
        return ScanTiming{180, 900, 160, 160, 120, 1};
    }
    if (normalized == QStringLiteral("reliable")) {
        return ScanTiming{850, 2600, 260, 430, 380, 3};
    }
    return ScanTiming{320, 1300, 190, 260, 220, 1};
}

QList<quint16> probePortsForProfile(const QString& profile) {
    const QString normalized = normalizedScanProfile(profile);
    if (normalized == QStringLiteral("fast")) {
        return {22, 23, 80, 81, 135, 443, 445, 548, 554, 631, 8000, 8008, 8080, 9100, 62078};
    }
    if (normalized == QStringLiteral("reliable")) {
        return {22, 23, 53, 80, 81, 88, 135, 139, 443, 445, 548, 554, 631, 1883, 3389, 5000, 5001, 5357, 5900, 7000, 8000, 8008, 8009, 8080, 8081, 8443, 8883, 8888, 9000, 9090, 9100, 32400, 62078};
    }
    return {22, 23, 80, 81, 135, 139, 443, 445, 548, 554, 631, 3389, 5000, 5001, 5357, 5900, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9100, 32400, 62078};
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

QStringList allBonjourServiceTypes() {
    QStringList services = priorityBonjourServiceTypes();
    const QStringList extraServices {
        QStringLiteral("_smb._tcp"),
        QStringLiteral("_ipp._tcp"),
        QStringLiteral("_printer._tcp"),
        QStringLiteral("_scanner._tcp"),
        QStringLiteral("_rtsp._tcp"),
        QStringLiteral("_hap._tcp"),
        QStringLiteral("_sleep-proxy._udp"),
    };
    for (const auto& service : extraServices) {
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
        resolvedNameByIpCache().insert(ip.trimmed(), CachedResolvedName{normalizedName, normalizedMac});
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

    static const QRegularExpression windowsNameRe(
        QStringLiteral("^\\s*Name:\\s*(\\S+)\\s*$"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption
    );
    const auto windowsNameMatch = windowsNameRe.match(output);
    if (windowsNameMatch.hasMatch()) {
        const QString normalized = normalizeResolvedName(windowsNameMatch.captured(1), ip);
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
    static const bool winsockReady = []() {
        WSADATA data {};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    if (!winsockReady) {
        return false;
    }

    SOCKET fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        return false;
    }

    u_long nonBlocking = 1;
    if (::ioctlsocket(fd, FIONBIO, &nonBlocking) != 0) {
        ::closesocket(fd);
        return false;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    const QByteArray ipBytes = ip.toUtf8();
    if (::inet_pton(AF_INET, ipBytes.constData(), &addr.sin_addr) != 1) {
        ::closesocket(fd);
        return false;
    }

    const int result = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (result == 0) {
        ::closesocket(fd);
        return true;
    }
    const int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL) {
        ::closesocket(fd);
        return false;
    }

    fd_set writeSet;
    fd_set exceptSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&exceptSet);
    FD_SET(fd, &writeSet);
    FD_SET(fd, &exceptSet);
    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;
    const int ready = ::select(0, nullptr, &writeSet, &exceptSet, &timeout);
    if (ready <= 0 || !FD_ISSET(fd, &writeSet)) {
        ::closesocket(fd);
        return false;
    }
    if (FD_ISSET(fd, &exceptSet)) {
        ::closesocket(fd);
        return false;
    }

    int socketError = 0;
    int errorLength = sizeof(socketError);
    bool ok = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &errorLength) == 0
        && socketError == 0;
    if (ok) {
        sockaddr_in peer {};
        int peerLength = sizeof(peer);
        ok = ::getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peerLength) == 0
            && peer.sin_family == AF_INET
            && peer.sin_addr.s_addr == addr.sin_addr.s_addr
            && peer.sin_port == addr.sin_port;
    }
    ::closesocket(fd);
    return ok;
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
    if (hasPort(QStringLiteral("631"))) {
        return QStringLiteral("printer");
    }
    if (hasPort(QStringLiteral("554"))) {
        return QStringLiteral("rtsp");
    }
    if (hasPort(QStringLiteral("445")) || hasPort(QStringLiteral("139"))) {
        return QStringLiteral("smb");
    }
    if (hasPort(QStringLiteral("548")) || hasPort(QStringLiteral("62078"))) {
        return QStringLiteral("apple");
    }
    if (hasPort(QStringLiteral("5000")) || hasPort(QStringLiteral("5001")) || hasPort(QStringLiteral("7000"))) {
        return QStringLiteral("media");
    }
    if (hasPort(QStringLiteral("8008")) || hasPort(QStringLiteral("8009"))) {
        return QStringLiteral("cast");
    }
    if (hasPort(QStringLiteral("32400"))) {
        return QStringLiteral("plex");
    }
    if (hasPort(QStringLiteral("1883")) || hasPort(QStringLiteral("8883"))) {
        return QStringLiteral("iot");
    }
    if (hasPort(QStringLiteral("443")) || hasPort(QStringLiteral("8443")) || hasPort(QStringLiteral("80")) || hasPort(QStringLiteral("81")) || hasPort(QStringLiteral("8080")) || hasPort(QStringLiteral("8081")) || hasPort(QStringLiteral("8888")) || hasPort(QStringLiteral("9000")) || hasPort(QStringLiteral("9090"))) {
        return QStringLiteral("web");
    }
    if (hasPort(QStringLiteral("3389"))) {
        return QStringLiteral("rdp");
    }
    if (hasPort(QStringLiteral("5900"))) {
        return QStringLiteral("vnc");
    }
    if (hasPort(QStringLiteral("135")) || hasPort(QStringLiteral("5357"))) {
        return QStringLiteral("windows");
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

QString inferTypeFromIdentity(const QString& hostName, const QString& vendor, bool isGateway, bool onLink) {
    const QString text = (hostName + QLatin1Char(' ') + vendor).trimmed().toLower();
    if (isGateway) {
        return QStringLiteral("router");
    }
    if (text.contains(QStringLiteral("apple"))
        || text.contains(QStringLiteral("iphone"))
        || text.contains(QStringLiteral("ipad"))
        || text.contains(QStringLiteral("macbook"))
        || text.contains(QStringLiteral("airplay"))
        || text.contains(QStringLiteral("appletv"))) {
        return QStringLiteral("apple");
    }
    if (text.contains(QStringLiteral("npi"))
        || text.contains(QStringLiteral("printer"))
        || text.contains(QStringLiteral("hewlett"))
        || text.contains(QStringLiteral("hp "))
        || text.contains(QStringLiteral("canon"))
        || text.contains(QStringLiteral("epson"))
        || text.contains(QStringLiteral("brother"))
        || text.contains(QStringLiteral("xerox"))) {
        return QStringLiteral("printer");
    }
    if (text.contains(QStringLiteral("camera"))
        || text.contains(QStringLiteral("hikvision"))
        || text.contains(QStringLiteral("dahua"))
        || text.contains(QStringLiteral("rtsp"))) {
        return QStringLiteral("camera");
    }
    if (text.contains(QStringLiteral("samsung"))
        || text.contains(QStringLiteral("lg electronics"))
        || text.contains(QStringLiteral("sony"))
        || text.contains(QStringLiteral("tv"))) {
        return QStringLiteral("media");
    }
    if (text.contains(QStringLiteral("google"))
        || text.contains(QStringLiteral("chromecast"))
        || text.contains(QStringLiteral("nest"))) {
        return QStringLiteral("cast");
    }
    if (text.contains(QStringLiteral("raspberry"))
        || text.contains(QStringLiteral("espressif"))
        || text.contains(QStringLiteral("tuya"))
        || text.contains(QStringLiteral("sonoff"))
        || text.contains(QStringLiteral("iot"))) {
        return QStringLiteral("iot");
    }
    return onLink ? QStringLiteral("arp") : QStringLiteral("-");
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
#ifdef Q_OS_WIN
    return QString::fromLocal8Bit(process.readAllStandardOutput());
#else
    return QString::fromUtf8(process.readAllStandardOutput());
#endif
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
    request += "\r\nUser-Agent: NetworkToolsQt/1.3.1\r\nAccept: */*\r\nConnection: close\r\n\r\n";
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
    const QByteArray query =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n";

    QHash<QString, QString> rawByIp;
    QHash<QString, QString> locationByIp;
    const auto sendQuery = [&]() {
        socket.writeDatagram(query, ssdpGroup, 1900);
    };

    QElapsedTimer timer;
    timer.start();
    sendQuery();
    bool sentRefresh = false;
    while (timer.elapsed() < timeoutMs) {
        if (!sentRefresh && timer.elapsed() > 650) {
            sendQuery();
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
        QString name;
        if (!location.isEmpty() && fetchedDescriptions < 48) {
            const QString description = fetchHttpText(QUrl(location), 700);
            if (!description.isEmpty()) {
                ++fetchedDescriptions;
                name = ssdpNameFromDescription(description, ip);
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
    QHash<QString, QStringList> ipsByHost;
    QSet<QString> queriedSrvInstances;
    QSet<QString> queriedHosts;
};

void materializeMdnsState(const QSet<QString>& scannedIps, MdnsResolutionState& state) {
    for (auto it = state.serviceByInstance.constBegin(); it != state.serviceByInstance.constEnd(); ++it) {
        const QString key = it.key();
        const QString serviceType = it.value();
        const QString instanceName = state.instanceByFullName.value(key);
        const QString targetHost = state.targetByInstance.value(key);
        const QString displayName = prettyBonjourName(serviceType, instanceName, targetHost);
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

void parseMdnsPacketIntoState(const QByteArray& packet, const QSet<QString>& scannedIps, MdnsResolutionState& state) {
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
                    state.serviceByInstance.insert(key, serviceType);
                    state.instanceByFullName.insert(key, instanceNameFromServiceName(pointerName, serviceType));
                }
            }
        } else if (type == 33 && dataLength >= 7) {
            int targetOffset = dataOffset + 6;
            const QString targetHost = decodeDnsName(packet, targetOffset);
            if (!targetHost.isEmpty()) {
                state.targetByInstance.insert(recordName.toLower(), targetHost);
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

    const auto sendQueries = [&]() {
        for (int index = 0; index < queries.size(); ++index) {
            socket.writeDatagram(queries.at(index), mdnsGroup, 5353);
            if ((index + 1) % 64 == 0) {
                QThread::msleep(2);
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
    bool sentRefresh = false;
    while (timer.elapsed() < timeoutMs) {
        if (!sentRefresh && timer.elapsed() > 350) {
            sendQueries();
            sentRefresh = true;
        }
        const int remaining = qMax(1, timeoutMs - static_cast<int>(timer.elapsed()));
        if (!socket.waitForReadyRead(qMin(80, remaining))) {
            continue;
        }
        while (socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket.pendingDatagramSize()));
            socket.readDatagram(datagram.data(), datagram.size());
            parseMdnsPacketIntoState(datagram, scannedIps, state);
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
        QTimer::singleShot(900, this, [this, records, finishedGeneration, finishedProfile]() {
            if (!m_cancelRequested.load() && m_activeGeneration.load() == finishedGeneration) {
                startNameEnrichment(records, finishedGeneration);
                startDetailEnrichment(records, finishedGeneration, finishedProfile, true);
                startRtspEnrichment(records, finishedGeneration);
            }
        });
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
    auto startMacs = captureArpTable(adapter.id);
    const QString adapterMac = adapterHardwareMac(adapter);
    if (!adapter.ip.trimmed().isEmpty() && adapterMac != QStringLiteral("-")) {
        startMacs.insert(adapter.ip, adapterMac);
    }
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
        seed.status = HostStatus::Online;
        seed.pingDisplay = linkPingDisplay();
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
        seed.typeHint = inferTypeFromIdentity(seed.hostName, seed.vendor, normalizeGatewayIp(seed.ip) == normalizeGatewayIp(seed.gateway), seed.onLink);
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
    QTimer::singleShot(40, this, [this, scheduledIps, generation]() {
        if (!m_cancelRequested.load() && generation == m_activeGeneration.load()) {
            startBonjourEnrichment(scheduledIps, generation);
        }
    });
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
                    const bool canImprovePing = canImprovePingDisplay(liveIt->pingDisplay, seed.pingDisplay);
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
                    return;
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
                    const bool canImprovePing = canImprovePingDisplay(liveIt->pingDisplay, record.pingDisplay);
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
                    return;
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
                }
                if (ping.success && !ping.display.trimmed().isEmpty()) {
                    QMutexLocker locker(&m_prefetchedPingMutex);
                    m_prefetchedPingDisplay.insert(ip, ping.display);
                }
                const bool isSelfAddress = isAdapterAddress(ip, adapter);
                const bool isGatewayAddress = normalizeGatewayIp(ip) == normalizeGatewayIp(record.gateway);
                if (ping.success && record.onLink && !hasUsableMac(record.mac) && !isSelfAddress && !isGatewayAddress) {
                    record.mac = lookupMac(ip);
                    if (!hasUsableMac(record.mac) && ping.resolvedName.isEmpty()) {
                        ping.success = false;
                        ping.display.clear();
                        QMutexLocker locker(&m_prefetchedPingMutex);
                        m_prefetchedPingDisplay.remove(ip);
                    }
                }
                if (record.onLink && !hasUsableMac(record.mac) && !isSelfAddress && !isGatewayAddress) {
                    return;
                }
                if (!ping.success
                    && (hasUsableMac(record.mac) || isSelfAddress || isGatewayAddress)
                    && !m_cancelRequested.load()
                    && generation == m_activeGeneration.load()) {
                    PingResult retry = retryPingHost(
                        ip,
                        adapter.ip,
                        quickPingTimeoutForProfile(activeScanProfile),
                        activeScanProfile == QStringLiteral("fast") ? 650 : 950,
                        activeScanProfile == QStringLiteral("fast") ? 110 : 150
                    );
                    if (retry.success) {
                        ping = retry;
                        if (!ping.display.trimmed().isEmpty()) {
                            QMutexLocker locker(&m_prefetchedPingMutex);
                            m_prefetchedPingDisplay.insert(ip, ping.display);
                        }
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
                } else if (record.onLink && hasUsableMac(record.mac)) {
                    record.status = HostStatus::Online;
                    record.pingDisplay = linkPingDisplay();
                    record.speed = QStringLiteral("link");
                    record.typeHint = inferTypeFromIdentity(record.hostName, record.vendor, normalizeGatewayIp(record.ip) == normalizeGatewayIp(record.gateway), record.onLink);
                }

                if (m_cancelRequested.load() || generation != m_activeGeneration.load()) {
                    return;
                }

                QStringList openPorts;
                if (ping.success || hasUsableMac(record.mac) || isSelfAddress || isGatewayAddress) {
                    openPorts = probeOpenPorts(ip, quickPortTimeoutForProfile(activeScanProfile), activeScanProfile);
                }
                bool enriched = false;
                if (!openPorts.isEmpty()) {
                    record.status = HostStatus::Online;
                    record.portsDisplay = openPorts.join(QLatin1Char(','));
                    record.port = record.portsDisplay;
                    record.webDetect = detectWebService(ip, openPorts);
                    record.typeHint = isGatewayAddress ? QStringLiteral("router") : detectTypeHint(openPorts, ping.success, record.onLink);
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

                if (isAppleTypeHint(record.typeHint) && isUnknownVendorLabel(record.vendor)) {
                    record.vendor = QStringLiteral("Apple, Inc.");
                    enriched = true;
                }
                const bool canPublishComplete = record.status != HostStatus::Offline
                    && (ping.success || !openPorts.isEmpty() || hasUsefulSeedSignal(record));
                if (canPublishComplete && !m_cancelRequested.load() && generation == m_activeGeneration.load()) {
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
                seed.status = HostStatus::Online;
                seed.pingDisplay = linkPingDisplay();
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
                seed.typeHint = inferTypeFromIdentity(seed.hostName, seed.vendor, normalizeGatewayIp(seed.ip) == normalizeGatewayIp(seed.gateway), seed.onLink);
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
                        seed.status = HostStatus::Online;
                        seed.pingDisplay = linkPingDisplay();
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
                        seed.typeHint = inferTypeFromIdentity(seed.hostName, seed.vendor, normalizeGatewayIp(seed.ip) == normalizeGatewayIp(seed.gateway), seed.onLink);
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

    QList<QString> mainScanIps = scheduledIps;
    if (activeScanProfile == QStringLiteral("fast")) {
        QSet<QString> mainSet;
        for (auto it = initialKnownMacs.constBegin(); it != initialKnownMacs.constEnd(); ++it) {
            if (scheduledIpSet.contains(it.key())) {
                mainSet.insert(it.key());
            }
        }
        if (!adapter.ip.trimmed().isEmpty() && scheduledIpSet.contains(adapter.ip)) {
            mainSet.insert(adapter.ip);
        }
        if (isValidGatewayIp(initialGateway) && scheduledIpSet.contains(initialGateway)) {
            mainSet.insert(initialGateway);
        }
        mainScanIps.clear();
        mainScanIps.reserve(mainSet.size());
        for (const auto& ip : scheduledIps) {
            if (mainSet.contains(ip)) {
                mainScanIps.append(ip);
            }
        }
        if (mainScanIps.isEmpty()) {
            mainScanIps = scheduledIps.mid(0, qMin(16, scheduledIps.size()));
        }
    }

    auto future = QtConcurrent::mapped(&m_scanPool, mainScanIps, [this, adapter, activeScanProfile](const QString& ip) {
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
    return m_watcher->isRunning() && !m_cancelRequested.load();
}

void NetworkScanService::startBonjourEnrichment(const QList<QString>& ips, quint64 generation) {
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
        rememberBonjourResolution(bonjourNames);
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
                        const bool isGateway = normalizeGatewayIp(updated.ip) == normalizeGatewayIp(updated.gateway);
                        const QString inferredType = inferTypeFromIdentity(updated.hostName, updated.vendor, isGateway, updated.onLink);
                        if (!inferredType.isEmpty()
                            && (isGateway
                                || updated.typeHint == QStringLiteral("mdns")
                                || updated.typeHint == QStringLiteral("icmp")
                                || updated.typeHint == QStringLiteral("udp")
                                || updated.typeHint == QStringLiteral("arp")
                                || updated.typeHint == QStringLiteral("web")
                                || updated.typeHint == QStringLiteral("media")
                                || isUnknownVendorLabel(updated.typeHint))) {
                            updated.typeHint = inferredType;
                        }
                        guard->m_liveRecords.insert(ip, updated);
                        shouldEmit = true;
                    } else if (bonjourNames.activeIps.contains(ip)) {
                        updated.ip = ip;
                        updated.generation = generation;
                        updated.status = HostStatus::Online;
                        updated.pingDisplay = linkPingDisplay();
                        updated.portsDisplay = QStringLiteral("-");
                        updated.port = QStringLiteral("-");
                        updated.webDetect = QStringLiteral("[n/a]");
                        updated.speed = QStringLiteral("mdns");
                        updated.typeHint = QStringLiteral("mdns");
                        updated.mac = guard->prefetchedMacForIp(ip);
                        updated.gateway = guard->cachedGateway();
                        updated.mask = guard->m_cachedMask;
                        updated.onLink = isOnLink(ip, guard->m_activeAdapter);
                        updated.hostName = resolvedName;
                        updated.vendor = resolvedName;
                        const QString inferredType = inferTypeFromIdentity(
                            updated.hostName,
                            updated.vendor,
                            normalizeGatewayIp(updated.ip) == normalizeGatewayIp(updated.gateway),
                            updated.onLink
                        );
                        if (!inferredType.isEmpty()) {
                            updated.typeHint = inferredType;
                        }
                        updated.name = routeDisplayForHost(guard->m_activeAdapter, updated);
                        recordMac = updated.mac;
                    }
                }
                if (!shouldEmit) {
                    rememberResolvedName(ip, recordMac, resolvedName);
                    QPointer<NetworkScanService> probeGuard = guard;
                    const QString probeIp = ip;
                    if (probeGuard) {
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

#ifdef Q_OS_MACOS
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
                        record.status = HostStatus::Online;
                        record.pingDisplay = linkPingDisplay();
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
                const bool isGateway = normalizeGatewayIp(record.ip) == normalizeGatewayIp(record.gateway);
                const bool weakCurrentType = isUnknownVendorLabel(record.typeHint)
                    || record.typeHint == QStringLiteral("icmp")
                    || record.typeHint == QStringLiteral("udp")
                    || record.typeHint == QStringLiteral("mdns")
                    || record.typeHint == QStringLiteral("arp");
                if (isGateway) {
                    if (record.typeHint != QStringLiteral("router")) {
                        record.typeHint = QStringLiteral("router");
                        changed = true;
                    }
                } else if (!discoveredType.isEmpty() && weakCurrentType) {
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

    QTimer::singleShot(2600, this, [guard, generation, scannedIps, adapterId, publishResolution]() {
        if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
            return;
        }
        (void)QtConcurrent::run(&guard->m_enrichmentPool, [guard, generation, scannedIps, adapterId, publishResolution]() {
            if (!guard || guard->m_cancelRequested.load() || guard->m_activeGeneration.load() != generation) {
                return;
            }
            const auto ssdp = collectSsdpDevices(scannedIps, adapterId, 1800);
            if (!isEmptySsdpResolution(ssdp)) {
                publishResolution(ssdp);
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
            const auto ssdp = collectSsdpDevices(scannedIps, adapterId, 2200);
            if (!isEmptySsdpResolution(ssdp)) {
                publishResolution(ssdp);
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
                    name = reverseLookupName(candidate.ip);
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

            if (isMissingPingDisplay(record.pingDisplay) || isLinkPingDisplay(record.pingDisplay)) {
                PingResult ping;
                if (isLinkPingDisplay(record.pingDisplay)) {
                    ping = NetworkScanService::pingHost(record.ip, adapter.ip, qBound(120, timing.pingTimeoutMs, 700));
                } else if (record.onLink || (!record.mac.trimmed().isEmpty() && record.mac != QStringLiteral("-"))) {
                    record.status = HostStatus::Online;
                    record.pingDisplay = linkPingDisplay();
                    record.speed = QStringLiteral("link");
                    changed = true;
                } else {
                    ping = NetworkScanService::pingHost(record.ip, adapter.ip, qBound(120, timing.pingTimeoutMs, 900));
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
                const bool isGateway = normalizeGatewayIp(record.ip) == normalizeGatewayIp(record.gateway);
                QString typeHint = isGateway ? QStringLiteral("router") : detectTypeHint(openPorts, pingSuccess, record.onLink);
                const QString identityType = inferTypeFromIdentity(record.hostName, record.vendor, isGateway, record.onLink);
                if (!identityType.isEmpty()
                    && (isGateway
                        || typeHint == QStringLiteral("icmp")
                        || typeHint == QStringLiteral("udp")
                        || typeHint == QStringLiteral("arp")
                        || typeHint == QStringLiteral("web")
                        || typeHint == QStringLiteral("media")
                        || isUnknownVendorLabel(typeHint))) {
                    typeHint = identityType;
                }
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
                if (isAppleTypeHint(record.typeHint) && isUnknownVendorLabel(record.vendor)) {
                    record.vendor = QStringLiteral("Apple, Inc.");
                    changed = true;
                }
            } else if (isUnknownVendorLabel(record.typeHint)) {
                const bool pingSuccess = !isMissingPingDisplay(record.pingDisplay);
                const QString typeHint = detectTypeHint({}, pingSuccess, record.onLink);
                if (record.typeHint != typeHint) {
                    record.typeHint = typeHint;
                    changed = true;
                }
                if (isAppleTypeHint(record.typeHint) && isUnknownVendorLabel(record.vendor)) {
                    record.vendor = QStringLiteral("Apple, Inc.");
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
            if (isAppleIdentity(record.hostName, record.vendor, record.typeHint) && isUnknownVendorLabel(record.vendor)) {
                record.vendor = QStringLiteral("Apple, Inc.");
                changed = true;
            }

            if (record.typeHint == QStringLiteral("-")
                || record.typeHint == QStringLiteral("icmp")
                || record.typeHint == QStringLiteral("udp")
                || record.typeHint == QStringLiteral("arp")
                || isUnknownVendorLabel(record.typeHint)) {
                const QString inferredType = inferTypeFromIdentity(
                    record.hostName,
                    record.vendor,
                    normalizeGatewayIp(record.ip) == normalizeGatewayIp(record.gateway),
                    record.onLink
                );
                if (!inferredType.isEmpty() && record.typeHint != inferredType) {
                    record.typeHint = inferredType;
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
    if (isAdapterAddress(ip, adapter)) {
        const QString selfMac = adapterHardwareMac(adapter);
        if (selfMac != QStringLiteral("-")) {
            row.mac = selfMac;
        }
    }
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
        } else if (resolvedName.isEmpty()) {
            resolvedName = cachedResolvedName(ip, row.mac);
        }
    }
    row.pingDisplay = ping.display.isEmpty() ? QStringLiteral("[n/a]") : ping.display;
    const bool isSelfAddress = isAdapterAddress(ip, adapter);
    const bool isGatewayAddress = normalizeGatewayIp(ip) == normalizeGatewayIp(row.gateway);
    if (ping.success && row.onLink && !hasUsableMac(row.mac) && !isSelfAddress && !isGatewayAddress) {
        row.mac = lookupMac(ip);
        if (!hasUsableMac(row.mac) && resolvedName.isEmpty()) {
            ping.success = false;
            ping.display.clear();
            row.pingDisplay = QStringLiteral("[n/a]");
        }
    }

    if (row.onLink && !hasUsableMac(row.mac) && !isSelfAddress && !isGatewayAddress) {
        row.status = HostStatus::Offline;
        row.pingDisplay = QStringLiteral("[n/a]");
        return row;
    }
    if (!ping.success && (hasUsableMac(row.mac) || isSelfAddress || isGatewayAddress) && !m_cancelRequested.load()) {
        const int retryWindowMs = scanProfile == QStringLiteral("fast") ? 850 : 1250;
        const int retryIntervalMs = scanProfile == QStringLiteral("fast") ? 120 : 170;
        PingResult retry = retryPingHost(
            ip,
            adapter.ip,
            qBound(120, timing.pingTimeoutMs, scanProfile == QStringLiteral("fast") ? 420 : 700),
            retryWindowMs,
            retryIntervalMs
        );
        if (retry.success) {
            ping = retry;
            row.pingDisplay = ping.display.isEmpty() ? QStringLiteral("online") : ping.display;
            if (resolvedName.isEmpty()) {
                resolvedName = ping.resolvedName;
            }
        }
    }

    QStringList openPorts;
    const bool linkConfirmed = hasUsableMac(row.mac) || isSelfAddress || isGatewayAddress;
    const bool shouldProbePorts = ping.success || linkConfirmed;
    if (shouldProbePorts && !m_cancelRequested.load()) {
        openPorts = probeOpenPorts(ip, timing.portTimeoutMs, scanProfile);
    }
    if (!ping.success && linkConfirmed) {
        row.pingDisplay = linkPingDisplay();
    }

    if (ping.success) {
        row.status = HostStatus::Online;
    } else if (linkConfirmed || !openPorts.isEmpty()) {
        row.status = HostStatus::Online;
        if (isMissingPingDisplay(row.pingDisplay)) {
            row.pingDisplay = linkPingDisplay();
        }
    } else {
        row.status = HostStatus::Offline;
    }

    row.vendor = resolvedName;
    if (row.status == HostStatus::Offline || m_cancelRequested.load()) {
        return row;
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
    const bool isGateway = normalizeGatewayIp(row.ip) == normalizeGatewayIp(row.gateway);
    row.typeHint = isGateway ? QStringLiteral("router") : detectTypeHint(openPorts, ping.success, row.onLink);
    const QString identityType = inferTypeFromIdentity(row.hostName, row.vendor, isGateway, row.onLink);
    if (!identityType.isEmpty()
        && (isGateway
            || row.typeHint == QStringLiteral("-")
            || row.typeHint == QStringLiteral("icmp")
            || row.typeHint == QStringLiteral("udp")
            || row.typeHint == QStringLiteral("arp")
            || row.typeHint == QStringLiteral("web")
            || row.typeHint == QStringLiteral("media"))) {
        row.typeHint = identityType;
    }
    if (isAppleTypeHint(row.typeHint) && isUnknownVendorLabel(row.vendor)) {
        row.vendor = QStringLiteral("Apple, Inc.");
    }
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
    const QByteArray ipBytes = ip.toUtf8();
    const IPAddr destination = ::inet_addr(ipBytes.constData());
    bool nativeIcmpAttempted = false;
    if (destination != INADDR_NONE) {
        HANDLE icmp = ::IcmpCreateFile();
        if (icmp != INVALID_HANDLE_VALUE) {
            nativeIcmpAttempted = true;
            const char payload[] = "NetworkTools";
            const DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 16;
            QByteArray replyBuffer(static_cast<int>(replySize), 0);
            const DWORD replies = ::IcmpSendEcho(
                icmp,
                destination,
                const_cast<char*>(payload),
                static_cast<WORD>(sizeof(payload)),
                nullptr,
                replyBuffer.data(),
                replySize,
                static_cast<DWORD>(qBound(80, timeoutMs, 1200))
            );
            if (replies > 0) {
                const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.constData());
                if (reply->Status == IP_SUCCESS && reply->Address == destination) {
                    result.success = true;
                    result.display = QStringLiteral("%1 ms").arg(qMax<DWORD>(1, reply->RoundTripTime));
                    ::IcmpCloseHandle(icmp);
                    return result;
                }
            }
            ::IcmpCloseHandle(icmp);
        }
    }
    if (nativeIcmpAttempted && !qEnvironmentVariableIsSet("NETWORKTOOLS_WIN_PING_EXE_FALLBACK")) {
        return result;
    }

    const auto runWindowsPing = [&](bool bindSource, int* status) {
        QStringList windowsArgs {
            QStringLiteral("-n"),
            QStringLiteral("1"),
            QStringLiteral("-w"),
            QString::number(qBound(80, timeoutMs, 1200)),
        };
        if (bindSource && !sourceIp.isEmpty()) {
            windowsArgs << QStringLiteral("-S") << sourceIp;
        }
        windowsArgs << ip;
        return runCommandCapture(QStringLiteral("ping"), windowsArgs, true, status);
    };
    QString output = runWindowsPing(!sourceIp.isEmpty(), &exitStatus);
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

#ifdef Q_OS_WIN
    const QString escapedIp = QRegularExpression::escape(ip);
    const auto parseWindowsReply = [&](const QString& pingOutput) {
        const QRegularExpression replyRe(
            QStringLiteral("^\\s*(?:Reply from|Ответ от)\\s+%1\\s*:\\s*(.+)$").arg(escapedIp),
            QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption
        );
        auto replyIt = replyRe.globalMatch(pingOutput);
        while (replyIt.hasNext()) {
            const QString replyText = replyIt.next().captured(1).trimmed();
            if (replyText.contains(QStringLiteral("unreachable"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("недоступ"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("timed out"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("TTL expired"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("истек"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("failure"), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("сбой"), Qt::CaseInsensitive)) {
                continue;
            }
            if (replyText.contains(QStringLiteral("ttl="), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("bytes="), Qt::CaseInsensitive)
                || replyText.contains(QStringLiteral("байт="), Qt::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    };

    if (parseWindowsReply(output)) {
        result.success = true;
        result.display = QStringLiteral("online");
        return result;
    }
    if (!sourceIp.isEmpty()) {
        int fallbackStatus = -1;
        const QString fallbackOutput = runWindowsPing(false, &fallbackStatus);
        result.resolvedName = result.resolvedName.isEmpty()
            ? extractResolvedNameFromPingOutput(fallbackOutput, ip)
            : result.resolvedName;
        const auto fallbackTimeMatch = timeRe.match(fallbackOutput);
        if (fallbackTimeMatch.hasMatch()) {
            QString value = fallbackTimeMatch.captured(1);
            value.replace(QLatin1Char(','), QLatin1Char('.'));
            const int pingMs = qMax(1, qRound(value.toDouble()));
            result.success = true;
            result.display = QStringLiteral("%1 ms").arg(pingMs);
            return result;
        }
        if (parseWindowsReply(fallbackOutput)) {
            result.success = true;
            result.display = QStringLiteral("online");
            return result;
        }
    }

    result.success = false;
    return result;
#else
    result.success = (exitStatus == 0);
    if (result.success) {
        result.display = QStringLiteral("online");
    }
    return result;
#endif
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
    const int boundedTimeoutMs = qBound(260, timeoutMs * 2, 1400);
    for (const auto port : ports) {
        if (tryConnectPort(ip, port, boundedTimeoutMs)) {
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
    if (containsValueInsensitive(openPorts, QStringLiteral("5001"))) {
        endpoints.append(QStringLiteral("https://%1:5001").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("80"))) {
        endpoints.append(QStringLiteral("http://%1").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("81"))) {
        endpoints.append(QStringLiteral("http://%1:81").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8000"))) {
        endpoints.append(QStringLiteral("http://%1:8000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8008"))) {
        endpoints.append(QStringLiteral("http://%1:8008").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8080"))) {
        endpoints.append(QStringLiteral("http://%1:8080").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("8081"))) {
        endpoints.append(QStringLiteral("http://%1:8081").arg(ip));
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
    if (containsValueInsensitive(openPorts, QStringLiteral("5000"))) {
        endpoints.append(QStringLiteral("http://%1:5000").arg(ip));
    }
    if (containsValueInsensitive(openPorts, QStringLiteral("7000"))) {
        endpoints.append(QStringLiteral("http://%1:7000").arg(ip));
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
#else
    entries = captureWindowsNeighborTable();
    const QString output = runCommandCapture(QStringLiteral("arp"), {QStringLiteral("-a")}, false, &exitStatus);
    if (exitStatus < 0) {
        return entries;
    }
    static const QRegularExpression lineRe(QStringLiteral("^\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([0-9a-fA-F:.\\-]+)\\s+(dynamic|static)\\s*$"),
                                           QRegularExpression::CaseInsensitiveOption);
    for (const QString& rawLine : output.split(QLatin1Char('\n'))) {
        const auto match = lineRe.match(rawLine.trimmed());
        if (!match.hasMatch()) {
            continue;
        }
        const QString type = match.captured(3).trimmed().toLower();
        if (type != QStringLiteral("dynamic")) {
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
    const QString reverseName = reverseLookupName(ip);
    if (!reverseName.isEmpty()) {
        return reverseName;
    }
    const auto hostInfo = QHostInfo::fromName(ip);
    const QString normalized = normalizeResolvedName(hostInfo.hostName(), ip);
    return normalized.isEmpty() ? QStringLiteral("-") : normalized;
}

QString NetworkScanService::detectGateway(const AdapterInfo& adapter) {
#ifdef Q_OS_WIN
    int exitStatus = -1;
    const QString output = runCommandCapture(QStringLiteral("route"), {QStringLiteral("print"), QStringLiteral("-4")}, false, &exitStatus);
    if (exitStatus < 0) {
        return QStringLiteral("-");
    }

    QString fallbackGateway;
    static const QRegularExpression defaultRouteRe(
        QStringLiteral("^\\s*0\\.0\\.0\\.0\\s+0\\.0\\.0\\.0\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+\\d+\\s*$"),
        QRegularExpression::MultilineOption
    );
    auto match = defaultRouteRe.globalMatch(output);
    while (match.hasNext()) {
        const auto route = match.next();
        const QString gateway = normalizeGatewayIp(route.captured(1));
        const QString routeInterface = route.captured(2).trimmed();
        if (!isValidGatewayIp(gateway)) {
            continue;
        }
        if (fallbackGateway.isEmpty()) {
            fallbackGateway = gateway;
        }
        if (!adapter.ip.trimmed().isEmpty() && routeInterface == adapter.ip.trimmed()) {
            return gateway;
        }
    }

    return fallbackGateway.isEmpty() ? QStringLiteral("-") : fallbackGateway;
#elif defined(Q_OS_MACOS)
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
