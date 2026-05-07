#include "core/VendorDbService.h"

#include "core/AppPaths.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QTemporaryFile>
#include <QTimer>

#include <algorithm>
#include <numeric>

namespace nt {

namespace {

constexpr auto kDefaultUrl = "https://www.wireshark.org/download/automated/data/manuf";

QStringList candidateUrls() {
    return {
        QString::fromLatin1(kDefaultUrl),
        QStringLiteral("https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"),
    };
}

QString normalizeVendorLabel(QString shortVendor, QString longVendor) {
    shortVendor = shortVendor.simplified();
    longVendor = longVendor.simplified();

    if (longVendor.isEmpty()) {
        return shortVendor;
    }
    if (shortVendor.isEmpty()) {
        return longVendor;
    }
    if (longVendor.compare(shortVendor, Qt::CaseInsensitive) == 0) {
        return longVendor;
    }
    if (longVendor.startsWith(shortVendor + QLatin1Char(' '), Qt::CaseInsensitive)
        || longVendor.startsWith(shortVendor + QLatin1Char(','), Qt::CaseInsensitive)
        || longVendor.startsWith(shortVendor + QLatin1Char('.'), Qt::CaseInsensitive)) {
        return longVendor;
    }
    return longVendor;
}

QString builtInVendorFallback(const QString& normalizedMac) {
    const QString prefix = normalizedMac.left(8);
    static const QSet<QString> applePrefixes {
        QStringLiteral("00:03:93"), QStringLiteral("00:05:02"), QStringLiteral("00:0a:27"),
        QStringLiteral("00:0a:95"), QStringLiteral("00:0d:93"), QStringLiteral("00:11:24"),
        QStringLiteral("00:14:51"), QStringLiteral("00:16:cb"), QStringLiteral("00:17:f2"),
        QStringLiteral("00:19:e3"), QStringLiteral("00:1b:63"), QStringLiteral("00:1c:b3"),
        QStringLiteral("00:1d:4f"), QStringLiteral("00:1e:c2"), QStringLiteral("00:1f:5b"),
        QStringLiteral("00:1f:f3"), QStringLiteral("00:21:e9"), QStringLiteral("00:22:41"),
        QStringLiteral("00:23:12"), QStringLiteral("00:23:32"), QStringLiteral("00:23:6c"),
        QStringLiteral("00:23:df"), QStringLiteral("00:24:36"), QStringLiteral("00:25:00"),
        QStringLiteral("00:25:4b"), QStringLiteral("00:25:bc"), QStringLiteral("00:26:08"),
        QStringLiteral("00:26:4a"), QStringLiteral("00:26:b0"), QStringLiteral("00:26:bb"),
        QStringLiteral("04:0c:ce"), QStringLiteral("04:15:52"), QStringLiteral("04:1e:64"),
        QStringLiteral("04:26:65"), QStringLiteral("04:4b:ed"), QStringLiteral("04:52:f3"),
        QStringLiteral("04:54:53"), QStringLiteral("04:69:f8"), QStringLiteral("04:db:56"),
        QStringLiteral("04:e5:36"), QStringLiteral("04:f1:3e"), QStringLiteral("08:00:07"),
        QStringLiteral("08:66:98"), QStringLiteral("08:70:45"), QStringLiteral("08:74:02"),
        QStringLiteral("0c:30:21"), QStringLiteral("0c:4d:e9"), QStringLiteral("0c:74:c2"),
        QStringLiteral("0c:77:1a"), QStringLiteral("10:9a:dd"), QStringLiteral("10:dd:b1"),
        QStringLiteral("14:10:9f"), QStringLiteral("14:20:5e"), QStringLiteral("14:5a:05"),
        QStringLiteral("18:20:32"), QStringLiteral("18:34:51"), QStringLiteral("18:65:90"),
        QStringLiteral("18:af:61"), QStringLiteral("18:e7:f4"), QStringLiteral("1c:1a:c0"),
        QStringLiteral("1c:ab:a7"), QStringLiteral("20:7d:74"), QStringLiteral("24:24:0e"),
        QStringLiteral("24:a0:74"), QStringLiteral("24:e3:14"), QStringLiteral("28:37:37"),
        QStringLiteral("28:6a:ba"), QStringLiteral("28:cf:e9"), QStringLiteral("2c:1f:23"),
        QStringLiteral("2c:33:61"), QStringLiteral("2c:54:cf"), QStringLiteral("2c:f0:a2"),
        QStringLiteral("30:10:e4"), QStringLiteral("30:35:ad"), QStringLiteral("30:63:6b"),
        QStringLiteral("34:08:bc"), QStringLiteral("34:12:98"), QStringLiteral("34:15:9e"),
        QStringLiteral("34:36:3b"), QStringLiteral("34:a3:95"), QStringLiteral("34:c0:59"),
        QStringLiteral("38:48:4c"), QStringLiteral("38:71:de"), QStringLiteral("38:c9:86"),
        QStringLiteral("3c:07:54"), QStringLiteral("3c:15:c2"), QStringLiteral("3c:22:fb"),
        QStringLiteral("3c:2e:f9"), QStringLiteral("3c:7d:0a"), QStringLiteral("40:30:04"),
        QStringLiteral("40:6c:8f"), QStringLiteral("40:a6:d9"), QStringLiteral("40:b3:95"),
        QStringLiteral("44:2a:60"), QStringLiteral("44:4c:0c"), QStringLiteral("44:d8:84"),
        QStringLiteral("48:43:7c"), QStringLiteral("48:60:bc"), QStringLiteral("48:a1:95"),
        QStringLiteral("4c:32:75"), QStringLiteral("4c:57:ca"), QStringLiteral("4c:74:bf"),
        QStringLiteral("50:32:37"), QStringLiteral("50:7a:55"), QStringLiteral("50:ea:d6"),
        QStringLiteral("54:26:96"), QStringLiteral("54:72:4f"), QStringLiteral("58:1f:aa"),
        QStringLiteral("58:55:ca"), QStringLiteral("58:b0:35"), QStringLiteral("5c:59:48"),
        QStringLiteral("5c:8d:4e"), QStringLiteral("60:03:08"), QStringLiteral("60:33:4b"),
        QStringLiteral("60:69:44"), QStringLiteral("60:f8:1d"), QStringLiteral("64:a3:cb"),
        QStringLiteral("64:b0:a6"), QStringLiteral("64:e6:82"), QStringLiteral("68:ab:1e"),
        QStringLiteral("68:d9:3c"), QStringLiteral("6c:40:08"), QStringLiteral("6c:70:9f"),
        QStringLiteral("70:11:24"), QStringLiteral("70:48:0f"), QStringLiteral("70:56:81"),
        QStringLiteral("70:73:cb"), QStringLiteral("74:e2:f5"), QStringLiteral("78:31:c1"),
        QStringLiteral("78:4f:43"), QStringLiteral("78:6c:1c"), QStringLiteral("7c:04:d0"),
        QStringLiteral("7c:6d:62"), QStringLiteral("7c:c3:a1"), QStringLiteral("80:00:6e"),
        QStringLiteral("80:49:71"), QStringLiteral("80:92:9f"), QStringLiteral("84:29:99"),
        QStringLiteral("84:38:35"), QStringLiteral("84:85:06"), QStringLiteral("84:fc:ac"),
        QStringLiteral("88:1f:a1"), QStringLiteral("88:53:95"), QStringLiteral("88:63:df"),
        QStringLiteral("8c:29:37"), QStringLiteral("8c:58:77"), QStringLiteral("8c:7b:9d"),
        QStringLiteral("8c:85:90"), QStringLiteral("90:27:e4"), QStringLiteral("90:60:f1"),
        QStringLiteral("90:b2:1f"), QStringLiteral("90:c1:15"), QStringLiteral("94:94:26"),
        QStringLiteral("98:01:a7"), QStringLiteral("98:03:d8"), QStringLiteral("98:5a:eb"),
        QStringLiteral("98:b8:e3"), QStringLiteral("9c:04:eb"), QStringLiteral("9c:20:7b"),
        QStringLiteral("9c:29:3f"), QStringLiteral("9c:35:eb"), QStringLiteral("a0:99:9b"),
        QStringLiteral("a4:5e:60"), QStringLiteral("a4:83:e7"), QStringLiteral("a4:b1:97"),
        QStringLiteral("a8:20:66"), QStringLiteral("a8:86:dd"), QStringLiteral("a8:bb:cf"),
        QStringLiteral("ac:bc:32"), QStringLiteral("b0:65:bd"), QStringLiteral("b0:ca:68"),
        QStringLiteral("b4:18:d1"), QStringLiteral("b4:f0:ab"), QStringLiteral("b8:09:8a"),
        QStringLiteral("b8:17:c2"), QStringLiteral("b8:53:ac"), QStringLiteral("b8:e8:56"),
        QStringLiteral("bc:3b:af"), QStringLiteral("bc:67:1c"), QStringLiteral("c0:1a:da"),
        QStringLiteral("c0:84:7a"), QStringLiteral("c0:cc:f8"), QStringLiteral("c4:2c:03"),
        QStringLiteral("c4:b3:01"), QStringLiteral("c8:2a:14"), QStringLiteral("c8:33:4b"),
        QStringLiteral("c8:69:cd"), QStringLiteral("c8:bc:c8"), QStringLiteral("cc:08:8d"),
        QStringLiteral("cc:20:e8"), QStringLiteral("cc:29:f5"), QStringLiteral("d0:03:4b"),
        QStringLiteral("d0:23:db"), QStringLiteral("d0:25:98"), QStringLiteral("d0:a6:37"),
        QStringLiteral("d0:e1:40"), QStringLiteral("d4:9a:20"), QStringLiteral("d4:f4:6f"),
        QStringLiteral("d8:30:62"), QStringLiteral("d8:96:95"), QStringLiteral("d8:bb:2c"),
        QStringLiteral("dc:2b:2a"), QStringLiteral("dc:37:14"), QStringLiteral("dc:41:5f"),
        QStringLiteral("e0:66:78"), QStringLiteral("e0:ac:cb"), QStringLiteral("e0:b5:2d"),
        QStringLiteral("e0:c9:7a"), QStringLiteral("e4:25:e7"), QStringLiteral("e4:8b:7f"),
        QStringLiteral("e4:ce:8f"), QStringLiteral("e8:04:0b"), QStringLiteral("e8:06:88"),
        QStringLiteral("e8:80:2e"), QStringLiteral("ec:35:86"), QStringLiteral("ec:85:2f"),
        QStringLiteral("f0:18:98"), QStringLiteral("f0:24:75"), QStringLiteral("f0:99:bf"),
        QStringLiteral("f0:b0:e7"), QStringLiteral("f4:0f:24"), QStringLiteral("f4:31:c3"),
        QStringLiteral("f4:5c:89"), QStringLiteral("f4:f5:d8"), QStringLiteral("f8:1e:df"),
        QStringLiteral("f8:27:93"), QStringLiteral("f8:4f:57"), QStringLiteral("fc:25:3f"),
        QStringLiteral("fc:e9:98"),
    };
    return applePrefixes.contains(prefix) ? QStringLiteral("Apple, Inc.") : QString();
}

} // namespace

VendorDbService::VendorDbService(QObject* parent)
    : QObject(parent) {
    AppPaths::ensureRuntimeTree();
}

bool VendorDbService::ensureReady(bool autoDownload) {
    {
        QMutexLocker locker(&m_mutex);
        if (m_loaded) {
            const QString status = m_status;
            locker.unlock();
            emit statusChanged(status, true);
            return true;
        }
    }
    const bool ok = loadFromDisk(autoDownload);
    emit statusChanged(statusText(), ok);
    return ok;
}

bool VendorDbService::seedBundledDb() {
    const QString seedPath = AppPaths::vendorSeedPath();
    if (!QFile::exists(seedPath) || QFile::exists(AppPaths::vendorDbPath())) {
        return false;
    }
    QDir().mkpath(AppPaths::dataDir());
    return QFile::copy(seedPath, AppPaths::vendorDbPath());
}

bool VendorDbService::loadFromDisk(bool autoDownload) {
    seedBundledDb();
    QByteArray data;
    QString sourcePath = AppPaths::vendorDbPath();
    QFile file(sourcePath);
    if (file.exists() && file.open(QIODevice::ReadOnly)) {
        data = file.readAll();
        file.close();
    }

    if (data.isEmpty()) {
        sourcePath = AppPaths::vendorSeedPath();
        QFile seedFile(sourcePath);
        if (seedFile.exists() && seedFile.open(QIODevice::ReadOnly)) {
            data = seedFile.readAll();
            seedFile.close();
        }
    }

    if (data.isEmpty() && autoDownload) {
        updateFromNetwork();
        sourcePath = AppPaths::vendorDbPath();
        QFile refreshedFile(sourcePath);
        if (refreshedFile.exists() && refreshedFile.open(QIODevice::ReadOnly)) {
            data = refreshedFile.readAll();
            refreshedFile.close();
        }
    }

    if (data.isEmpty()) {
        {
            QMutexLocker locker(&m_mutex);
            m_status = QStringLiteral("База вендоров: недоступна");
            m_loaded = false;
        }
        return false;
    }
    if (!parseManuf(data)) {
        {
            QMutexLocker locker(&m_mutex);
            m_status = QStringLiteral("База вендоров: ошибка разбора");
            m_loaded = false;
        }
        return false;
    }

    int entries = 0;
    {
        QMutexLocker locker(&m_mutex);
        entries = std::accumulate(m_byBits.begin(), m_byBits.end(), 0, [](int sum, const auto& value) {
            return sum + value.size();
        });
    }
    const bool fromBundle = sourcePath == AppPaths::vendorSeedPath();
    {
        QMutexLocker locker(&m_mutex);
        m_status = fromBundle
            ? QStringLiteral("База вендоров: bundle (%1 записей)").arg(entries)
            : QStringLiteral("База вендоров: готова (%1 записей)").arg(entries);
        m_loaded = entries > 0;
        return m_loaded;
    }
}

bool VendorDbService::updateFromNetwork(int timeoutMs) {
    QNetworkAccessManager manager;
    bool ok = false;

    for (const auto& urlString : candidateUrls()) {
        QNetworkRequest request{QUrl(urlString)};
        request.setTransferTimeout(timeoutMs);
    request.setRawHeader("User-Agent", QByteArrayLiteral("NetWorkToolsQt/1.0.9"));

        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        QNetworkReply* reply = manager.get(request);
        connect(&timer, &QTimer::timeout, &loop, [&]() {
            if (reply != nullptr) {
                reply->abort();
            }
            loop.quit();
        });
        connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timer.start(timeoutMs);
        loop.exec();

        const QByteArray data = reply->readAll();
        const auto error = reply->error();
        reply->deleteLater();
        if (error != QNetworkReply::NoError || data.size() < 10000) {
            continue;
        }

        QSaveFile out(AppPaths::vendorDbPath());
        if (!out.open(QIODevice::WriteOnly)) {
            break;
        }
        out.write(data);
        if (!out.commit()) {
            break;
        }
        ok = true;
        break;
    }

    if (!ok) {
        {
            QMutexLocker locker(&m_mutex);
            m_status = QStringLiteral("База вендоров: ошибка загрузки");
        }
        emit statusChanged(statusText(), false);
        return false;
    }

    const bool ready = loadFromDisk(false);
    emit statusChanged(statusText(), ready);
    return ready;
}

QString VendorDbService::normalizeMac(const QString& mac) {
    QString value = mac.trimmed().toLower();
    value.replace(QLatin1Char('-'), QLatin1Char(':'));
    if (value.contains(QLatin1Char('.'))) {
        QString hex = value;
        hex.remove(QLatin1Char('.'));
        if (hex.size() != 12) {
            return QString();
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
                return QString();
            }
            parts.append(part.rightJustified(2, QLatin1Char('0')));
        }
        return parts.join(QLatin1Char(':'));
    }

    QString hex = value;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9a-f]")));
    if (hex.size() != 12) {
        return QString();
    }
    QStringList parts;
    for (int index = 0; index < hex.size(); index += 2) {
        parts.append(hex.mid(index, 2));
    }
    return parts.join(QLatin1Char(':'));
}

bool VendorDbService::parsePrefixToken(const QString& token, quint64& prefixValue, int& bits) {
    QString text = token.trimmed();
    bits = -1;
    const int slashIndex = text.indexOf(QLatin1Char('/'));
    if (slashIndex >= 0) {
        bits = text.mid(slashIndex + 1).toInt();
        text = text.left(slashIndex).trimmed();
    }

    QString hex = text;
    hex.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
    if (hex.isEmpty()) {
        return false;
    }
    const int sourceBits = hex.size() * 4;
    if (bits < 0) {
        bits = sourceBits;
    }
    bool ok = false;
    prefixValue = hex.left(12).toULongLong(&ok, 16);
    if (!ok || bits <= 0 || bits > 48) {
        return false;
    }
    if (sourceBits > bits) {
        prefixValue >>= (sourceBits - bits);
    } else if (sourceBits < bits) {
        prefixValue <<= (bits - sourceBits);
    }
    return true;
}

bool VendorDbService::parseManuf(const QByteArray& data) {
    QHash<int, QHash<quint64, QString>> parsed;
    const QList<QByteArray> lines = data.split('\n');
    for (const auto& rawLine : lines) {
        const QString line = QString::fromUtf8(rawLine).section(QLatin1Char('#'), 0, 0).trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }

        QString prefixToken;
        QString shortVendor;
        QString longVendor;

        const QStringList tabParts = line.split(QRegularExpression(QStringLiteral("\\t+")), Qt::SkipEmptyParts);
        if (tabParts.size() >= 2) {
            prefixToken = tabParts.at(0).trimmed();
            shortVendor = tabParts.at(1).trimmed();
            longVendor = tabParts.value(2).trimmed();
        } else {
            const QStringList parts = line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
            if (parts.size() < 2) {
                continue;
            }
            prefixToken = parts.at(0).trimmed();
            shortVendor = parts.at(1).trimmed();
            longVendor = parts.mid(2).join(QLatin1Char(' ')).trimmed();
        }

        if (prefixToken.isEmpty() || shortVendor.isEmpty()) {
            continue;
        }

        quint64 prefixValue = 0;
        int bits = -1;
        if (!parsePrefixToken(prefixToken, prefixValue, bits)) {
            continue;
        }

        const QString vendor = normalizeVendorLabel(shortVendor, longVendor).trimmed();
        if (vendor.isEmpty()) {
            continue;
        }

        parsed[bits].insert(prefixValue, vendor);
    }
    if (parsed.isEmpty()) {
        return false;
    }
    QMutexLocker locker(&m_mutex);
    m_byBits = parsed;
    return true;
}

QString VendorDbService::lookupVendor(const QString& mac) const {
    const QString normalized = normalizeMac(mac);
    if (normalized.isEmpty()) {
        return QStringLiteral("unknown vendor");
    }

    QString hex = normalized;
    hex.remove(QLatin1Char(':'));
    bool ok = false;
    const quint64 full = hex.toULongLong(&ok, 16);
    if (!ok) {
        return QStringLiteral("unknown vendor");
    }

    QMutexLocker locker(&m_mutex);
    if (!m_loaded) {
        const QString fallback = builtInVendorFallback(normalized);
        return fallback.isEmpty() ? QStringLiteral("unknown vendor") : fallback;
    }

    QList<int> bitWidths = m_byBits.keys();
    std::sort(bitWidths.begin(), bitWidths.end(), std::greater<int>());
    for (const int bits : bitWidths) {
        const quint64 masked = bits >= 48 ? full : (full >> (48 - bits));
        const auto map = m_byBits.value(bits);
        const auto it = map.constFind(masked);
        if (it != map.constEnd()) {
            return it.value();
        }
    }

    const QString fallback = builtInVendorFallback(normalized);
    return fallback.isEmpty() ? QStringLiteral("unknown vendor") : fallback;
}

QString VendorDbService::statusText() const {
    QMutexLocker locker(&m_mutex);
    return m_status;
}

QString VendorDbService::dbPath() const {
    return AppPaths::vendorDbPath();
}

} // namespace nt
