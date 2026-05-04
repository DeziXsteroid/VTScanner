#pragma once

#include <QHash>
#include <QMutex>
#include <QObject>

namespace nt {

class VendorDbService final : public QObject {
    Q_OBJECT

public:
    explicit VendorDbService(QObject* parent = nullptr);

    bool ensureReady(bool autoDownload = true);
    bool updateFromNetwork(int timeoutMs = 8000);
    QString lookupVendor(const QString& mac) const;
    QString statusText() const;
    QString dbPath() const;

signals:
    void statusChanged(const QString& status, bool available);

private:
    bool seedBundledDb();
    bool loadFromDisk(bool autoDownload);
    bool parseManuf(const QByteArray& data);
    static QString normalizeMac(const QString& mac);
    static bool parsePrefixToken(const QString& token, quint64& prefixValue, int& bits);

    mutable QMutex m_mutex;
    QHash<int, QHash<quint64, QString>> m_byBits;
    bool m_loaded {false};
    QString m_status;
};

} // namespace nt
