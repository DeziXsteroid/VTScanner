#pragma once

#include "core/Types.h"

#include <QStringList>

#include <atomic>
#include <QFutureWatcher>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QSet>
#include <QThreadPool>

namespace nt {

class VendorDbService;

class NetworkScanService final : public QObject {
    Q_OBJECT

public:
    explicit NetworkScanService(VendorDbService* vendorDb, QObject* parent = nullptr);
    ~NetworkScanService() override;

    QList<AdapterInfo> adapters() const;
    RangeSuggestion suggestRange() const;

    void start(const QString& startIp, const QString& endIp, const QString& adapterId, int maxWorkers, const QString& scanProfile, quint64 generation);
    void cancel();
    bool isRunning() const;

signals:
    void scanStarted();
    void recordReady(const nt::ScanRecord& record);
    void scanFinished(const QList<nt::ScanRecord>& records, int durationMs);
    void scanFailed(const QString& errorText);

private:
    struct PingResult {
        bool success {false};
        QString display;
        QString resolvedName;
    };

    ScanRecord probeHost(const QString& ip, const AdapterInfo& adapter, const QString& scanProfile);
    static PingResult retryPingHost(const QString& ip, const QString& sourceIp, int pingTimeoutMs, int windowMs, int intervalMs);
    static bool isVpnName(const QString& name);
    static QList<QString> expandRange(const QString& startIp, const QString& endIp);
    static quint32 ipToInt(const QString& ip);
    static QString intToIp(quint32 value);
    static QHash<QString, QString> sweepPingRange(const QString& startIp, const QString& endIp, const AdapterInfo& adapter, const QString& scanProfile);
    static QHash<QString, QString> captureArpTable(const QString& adapterId = QString());
    static PingResult pingHost(const QString& ip, const QString& sourceIp, int timeoutMs);
    static QStringList probeOpenPorts(const QString& ip, int timeoutMs, const QString& scanProfile);
    static QString detectWebService(const QString& ip, const QStringList& openPorts);
    static QString lookupMac(const QString& ip);
    static QString resolveName(const QString& ip);
    static QString detectGateway(const AdapterInfo& adapter);
    static QString detectMask(const AdapterInfo& adapter);
    static bool isOnLink(const QString& ip, const AdapterInfo& adapter);
    void startBonjourEnrichment(const QList<QString>& ips, quint64 generation);
    void startRtspEnrichment(const QList<ScanRecord>& records, quint64 generation);
    void startNameEnrichment(const QList<ScanRecord>& records, quint64 generation);
    void startDetailEnrichment(const QList<ScanRecord>& records, quint64 generation, const QString& scanProfile);
    void publishLiveRecord(ScanRecord record);
    QString cachedGateway() const;
    void setCachedGateway(const QString& gateway);
    QString prefetchedMacForIp(const QString& ip) const;
    QHash<QString, QString> prefetchedMacsSnapshot() const;
    void setPrefetchedMacs(const QHash<QString, QString>& macs);
    void mergePrefetchedMacs(const QHash<QString, QString>& macs);
    AdapterInfo adapterById(const QString& adapterId) const;

    VendorDbService* m_vendorDb {nullptr};
    QFutureWatcher<nt::ScanRecord>* m_watcher {nullptr};
    std::atomic_bool m_cancelRequested {false};
    qint64 m_startedMs {0};
    std::atomic<quint64> m_activeGeneration {0};
    AdapterInfo m_activeAdapter;
    QString m_activeScanProfile;
    mutable QMutex m_routeMutex;
    QString m_cachedGateway;
    QString m_cachedMask;
    mutable QMutex m_prefetchedPingMutex;
    QHash<QString, QString> m_prefetchedPingDisplay;
    mutable QMutex m_prefetchedMacsMutex;
    QHash<QString, QString> m_prefetchedMacs;
    mutable QMutex m_liveRecordsMutex;
    QHash<QString, ScanRecord> m_liveRecords;
    mutable QMutex m_nameEnrichmentMutex;
    QSet<QString> m_nameEnrichmentInFlight;
    QThreadPool m_scanPool;
};

} // namespace nt
