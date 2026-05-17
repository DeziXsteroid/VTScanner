#pragma once

#include "core/Types.h"

#include <QColor>
#include <QMainWindow>
#include <QMap>
#include <QSet>
#include <QTextCharFormat>

class QComboBox;
class QCheckBox;
class QAction;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPoint;
class QPushButton;
class QEvent;
class QMenu;
class QNetworkAccessManager;
class QSpinBox;
class QStackedWidget;
class QTableWidget;
class QTableWidgetItem;
class QTextEdit;
class QTimer;
class QToolButton;

namespace nt {
class HttpRequestService;
class NetworkScanService;
#ifndef Q_OS_ANDROID
class SerialSession;
#endif
class SettingsService;
class SnapshotService;
class SshProcessSession;
class TcpClientSession;
class TelnetSession;
class UdpSocketSession;
class VendorDbService;
}

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* object, QEvent* event) override;

private:
    struct SessionWidgets {
        QListWidget* profiles {nullptr};
        QLineEdit* nameEdit {nullptr};
        QLineEdit* hostEdit {nullptr};
        QSpinBox* portSpin {nullptr};
        QLineEdit* userEdit {nullptr};
        QLineEdit* passEdit {nullptr};
        QPushButton* connectButton {nullptr};
        QPushButton* saveButton {nullptr};
        QLabel* statusLabel {nullptr};
        QTextEdit* outputBox {nullptr};
        QLineEdit* inputEdit {nullptr};
    };

    struct SnmpWidgets {
        QLineEdit* hostEdit {nullptr};
        QSpinBox* portSpin {nullptr};
        QComboBox* versionCombo {nullptr};
        QLineEdit* communityEdit {nullptr};
        QLineEdit* writeCommunityEdit {nullptr};
        QStackedWidget* securityStack {nullptr};
        QLineEdit* filterEdit {nullptr};
        QLineEdit* v3UserEdit {nullptr};
        QComboBox* v3SecurityLevelCombo {nullptr};
        QComboBox* v3AuthProtocolCombo {nullptr};
        QLineEdit* v3AuthPasswordEdit {nullptr};
        QComboBox* v3PrivacyProtocolCombo {nullptr};
        QLineEdit* v3PrivacyPasswordEdit {nullptr};
        QPushButton* loadButton {nullptr};
        QPushButton* communityLoadButton {nullptr};
        QLabel* statusLabel {nullptr};
        QTableWidget* table {nullptr};
    };

    struct StreamWidgets {
        QTextEdit* outputBox {nullptr};
        QLineEdit* inputEdit {nullptr};
        QCheckBox* hexCheck {nullptr};
        QComboBox* eolCombo {nullptr};
        QPushButton* connectButton {nullptr};
        QList<QLineEdit*> quickEdits;
    };

#ifndef Q_OS_ANDROID
    struct SerialWidgets : StreamWidgets {
        QComboBox* portCombo {nullptr};
        QComboBox* baudCombo {nullptr};
        QComboBox* bitsCombo {nullptr};
        QComboBox* parityCombo {nullptr};
        QComboBox* stopBitsCombo {nullptr};
        QComboBox* flowControlCombo {nullptr};
    };
#endif

    struct TcpWidgets : StreamWidgets {
        QLineEdit* hostEdit {nullptr};
        QSpinBox* portSpin {nullptr};
        QSpinBox* localPortSpin {nullptr};
        QCheckBox* noDelayCheck {nullptr};
        QCheckBox* keepAliveCheck {nullptr};
        QCheckBox* autoPortCheck {nullptr};
    };

    struct UdpWidgets : StreamWidgets {
        QLineEdit* hostEdit {nullptr};
        QSpinBox* remotePortSpin {nullptr};
        QSpinBox* localPortSpin {nullptr};
        QCheckBox* reuseAddressCheck {nullptr};
        QCheckBox* autoPortCheck {nullptr};
    };

    void buildUi();
    void configureMenuBar();
    void applyDarkPalette();
    void applyStyleSheet();
    QWidget* createHeader();
    QWidget* createSidebar();
    QWidget* createScanPage();
    QWidget* createRequestPage();
#ifndef Q_OS_ANDROID
    QWidget* createSerialPage();
#endif
    QWidget* createTcpPage();
    QWidget* createUdpPage();
    QWidget* createSessionPage(const QString& kind, SessionWidgets& widgets, quint16 defaultPort);
    QWidget* createSnmpPage();
    QWidget* createSearchPortsPage();
    QWidget* createNetworkMonitoringPage();
    QWidget* createPlaceholderPage(const QString& title, const QString& text);
    void syncCurrentPage(int row);

    void openSettingsDialog();
    void reloadAdapters();
    void applySuggestedRange();
    void applyRangeFromCurrentAdapter();
    void resolveHostnameRange();
    bool isLightTheme() const;
    void refreshScanTableColors();
    void animateScanButtonPulse();
    void startScan();
    void stopScan();
    void saveSnapshot();
    void deleteSnapshot();
    void compareSnapshot();
    void compareSnapshotPath(const QString& path);
    void refreshFavoritesMenu();
    void showSnapshotDiffDialog(const nt::SnapshotMeta& meta, const nt::SnapshotDiffSummary& summary);
    void clearScanTable();
    void rebuildScanTable();
    void applyScanTableFilter();
    void applyScanColumnVisibility();
    void saveScanColumnVisibility() const;
    void applyScanColumnWidths();
    void saveScanColumnWidths() const;
    void updateScanSortButton();
    void toggleScanSortOrder();
    void refreshScanToolbarIcons();
    void updateScanProfileButton();
    void updateScanPingHealthButton();
    void setScanPingHealthColors(bool enabled);
    void setScanProfile(const QString& profile);
    void resetScanLog();
    void appendScanLogLine(const QString& line);
    void openScanLog();
    bool scanBackgroundRefreshEnabled() const;
    void updateScanBackgroundRefreshTimer();
    void startScanBackgroundRefresh();
    void finalizeScanBackgroundRefresh(const QList<nt::ScanRecord>& records, int durationMs);
    void appendScanRecord(const nt::ScanRecord& record);
    void finalizeScan(const QList<nt::ScanRecord>& records, int durationMs);
    void updateScanSummary();
    void updateScanFooter(const QString& stateText = QString());
    void updateSelectedHostPanel();
    void toggleScanCompareMode(bool enabled);
    void refreshScanComparisonBadges();
    void showScanCellDetails(int row, int column);
    void maybeShowScanCellHover(const QPoint& viewportPosition);
    void openScanContextMenu(const QPoint& position);
    void openScanRowInBrowser(int row);
    void openScanRowPing(int row);
    void openScanRowSession(const QString& kind, int row);
    void prepareSessionFromScan(SessionWidgets& widgets, const QString& host, quint16 port, const QString& kindLabel, int pageIndex);
    nt::SessionProfile currentSnmpProfile() const;
    void loadSnmpOidList();
    void applySnmpSelectedValue();
    void handleSnmpValueEdited(QTableWidgetItem* item);
    void refreshSnmpVersionUi();
    void applySnmpTableFilter();
    void persistSnmpSettingsFromUi();
    QStringList currentSnmpAuthArgs(bool forWrite, QString* errorText = nullptr) const;
    static int findRowByIp(QTableWidget* table, const QString& ip);

    void sendHttpRequest();
    void openHttpHistory();
#ifndef Q_OS_ANDROID
    void refreshSerialPorts();
    void toggleSerial();
#endif
    void toggleTcp();
    void toggleUdp();
#ifndef Q_OS_ANDROID
    void sendSerialPayload();
#endif
    void sendTcpPayload();
    void sendUdpPayload();
    static QByteArray payloadFromText(const QString& text, bool hexEnabled);
    static QString displayBytes(const QByteArray& bytes, bool hexEnabled);
    static QByteArray applyLineEnding(QByteArray payload, const QString& eolName, bool hexEnabled);
    void appendTrafficEntry(QTextEdit* box, const QColor& arrowColor, const QString& direction, const QString& payload, const QString& endpoint = QString());
    void loadQuickCommands(const QString& key, StreamWidgets& widgets);
    void saveQuickCommands(const QString& key, const StreamWidgets& widgets);
    void sendQuickCommand(const QString& key, StreamWidgets& widgets, int index);
    void loadSessionProfiles(const QString& kind, SessionWidgets& widgets, quint16 defaultPort);
    void applySessionProfile(const nt::SessionProfile& profile, SessionWidgets& widgets);
    nt::SessionProfile currentSessionProfile(const SessionWidgets& widgets, quint16 defaultPort) const;
    void saveSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort);
    void deleteSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort);
    void newSessionProfile(SessionWidgets& widgets, quint16 defaultPort);
    void sendSessionTerminalBytes(QTextEdit* box, const QByteArray& bytes);
    void appendSessionTerminalOutput(QTextEdit* box, const QString& text);
    void renderSessionDraft(QTextEdit* box);
    void removeSessionDraft(QTextEdit* box);
    QString* sessionDraftForBox(QTextEdit* box);
    int* sessionDraftCursorForBox(QTextEdit* box);
    QTextCharFormat* sessionTerminalFormatForBox(QTextEdit* box);
    QTextCharFormat sessionBaseTerminalFormat() const;
    QColor terminalTextColor() const;
    void refreshTerminalFormats();
    void openSessionSettings(const QString& kind, SessionWidgets& widgets);
    void runPortSearch();
    void refreshNetworkMonitoring();
    void showUpdateDialog(bool automatic);
    void checkForUpdates(bool automatic);

    nt::SettingsService* m_settings {nullptr};
    nt::VendorDbService* m_vendorDb {nullptr};
    nt::SnapshotService* m_snapshots {nullptr};
    nt::NetworkScanService* m_scanner {nullptr};
    nt::HttpRequestService* m_http {nullptr};
#ifndef Q_OS_ANDROID
    nt::SerialSession* m_serialSession {nullptr};
#endif
    nt::SshProcessSession* m_sshSession {nullptr};
    nt::TcpClientSession* m_tcpSession {nullptr};
    nt::TelnetSession* m_telnetSession {nullptr};
    nt::UdpSocketSession* m_udpSession {nullptr};

    QListWidget* m_navList {nullptr};
    QStackedWidget* m_pages {nullptr};
    QMenu* m_favoritesMenu {nullptr};

    QLineEdit* m_scanStartIp {nullptr};
    QLineEdit* m_scanEndIp {nullptr};
    QCheckBox* m_scanAutoIpCheck {nullptr};
    QCheckBox* m_scanAutoScanCheck {nullptr};
    QComboBox* m_scanAdapterCombo {nullptr};
    QComboBox* m_scanPrefixCombo {nullptr};
    QLabel* m_scanOnlineLabel {nullptr};
    QLabel* m_scanFooterStateLabel {nullptr};
    QLabel* m_scanFooterDisplayLabel {nullptr};
    QLabel* m_scanFooterThreadsLabel {nullptr};
    QLineEdit* m_scanFilterEdit {nullptr};
    QTableWidget* m_scanTable {nullptr};
    QPushButton* m_scanStartButton {nullptr};
    QPushButton* m_scanSortButton {nullptr};
    QPushButton* m_scanStopButton {nullptr};
    QToolButton* m_scanToolsButton {nullptr};
    QToolButton* m_scanProfileButton {nullptr};
    QToolButton* m_scanPingHealthButton {nullptr};
    QMenu* m_scanToolsMenu {nullptr};
    QMenu* m_scanProfileMenu {nullptr};
    QMap<int, QAction*> m_scanColumnActions;
    QMap<QString, QAction*> m_scanProfileActions;
    QTimer* m_scanAutoScanTimer {nullptr};
    QTimer* m_scanColumnWidthSaveTimer {nullptr};
    QTimer* m_scanBackgroundRefreshTimer {nullptr};
#ifndef Q_OS_ANDROID
    QTimer* m_serialPortRefreshTimer {nullptr};
#endif
    QTimer* m_networkMonitorTimer {nullptr};
    QMap<QString, QLabel*> m_hostLabels;
    QList<nt::ScanRecord> m_scanRows;
    QSet<QString> m_scanComparisonBaseline;
    QSet<QString> m_scanNewIps;
    QMap<QString, int> m_scanRefreshMisses;
    bool m_scanCompareMode {false};
    bool m_scanCompareHasBaseline {false};
    bool m_scanSortAscending {true};
    bool m_scanLaunchPending {false};
    bool m_scanPolishingActive {false};
    bool m_scanBackgroundRefreshRun {false};
    bool m_scanFollowupRunning {false};
    bool m_scanStopRequested {false};
    bool m_scanRestartAfterStop {false};
    QString m_scanLogPath;
    QString m_lastScanStartIp;
    QString m_lastScanEndIp;
    QString m_lastScanAdapterId;
    QString m_lastScanProfile;
    int m_lastScanWorkers {0};
    int m_scanFollowupRemaining {0};
    quint64 m_currentScanGeneration {0};

    QComboBox* m_requestMethodCombo {nullptr};
    QLineEdit* m_requestUrlEdit {nullptr};
    QLineEdit* m_requestUserEdit {nullptr};
    QLineEdit* m_requestPassEdit {nullptr};
    QSpinBox* m_requestTimeoutSpin {nullptr};
    QPlainTextEdit* m_requestHeadersEdit {nullptr};
    QPlainTextEdit* m_requestParamsEdit {nullptr};
    QPlainTextEdit* m_requestBodyEdit {nullptr};
    QTextEdit* m_requestResponseEdit {nullptr};

#ifndef Q_OS_ANDROID
    SerialWidgets m_serialWidgets;
#endif
    TcpWidgets m_tcpWidgets;
    UdpWidgets m_udpWidgets;
    SessionWidgets m_sshWidgets;
    SessionWidgets m_telnetWidgets;
    SnmpWidgets m_snmpWidgets;
    QLineEdit* m_portSearchHostEdit {nullptr};
    QLineEdit* m_portSearchRangeStartEdit {nullptr};
    QLineEdit* m_portSearchRangeEndEdit {nullptr};
    QPushButton* m_portSearchButton {nullptr};
    QPushButton* m_portSearchRangeButton {nullptr};
    QTableWidget* m_portSearchTable {nullptr};
    QLabel* m_portSearchStatusLabel {nullptr};
    QTableWidget* m_networkMonitorTable {nullptr};
    QTextEdit* m_networkMonitorDetails {nullptr};
    QLabel* m_networkMonitorStatusLabel {nullptr};
    QPushButton* m_networkMonitorToggleButton {nullptr};
    QNetworkAccessManager* m_updateManager {nullptr};
    QString m_sshDraft;
    QString m_telnetDraft;
    int m_sshDraftCursor {0};
    int m_telnetDraftCursor {0};
    QTextCharFormat m_sshTerminalBaseFormat;
    QTextCharFormat m_telnetTerminalBaseFormat;
    QTextCharFormat m_sshTerminalFormat;
    QTextCharFormat m_telnetTerminalFormat;
    bool m_snmpTablePopulating {false};
};
