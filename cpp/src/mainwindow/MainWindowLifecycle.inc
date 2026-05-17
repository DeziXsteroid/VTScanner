MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_settings(new nt::SettingsService(this))
    , m_vendorDb(new nt::VendorDbService(this))
    , m_snapshots(new nt::SnapshotService(this))
    , m_scanner(new nt::NetworkScanService(m_vendorDb, this))
    , m_http(new nt::HttpRequestService(this))
#ifndef Q_OS_ANDROID
    , m_serialSession(new nt::SerialSession(this))
#endif
    , m_sshSession(new nt::SshProcessSession(this))
    , m_tcpSession(new nt::TcpClientSession(this))
    , m_telnetSession(new nt::TelnetSession(this))
    , m_udpSession(new nt::UdpSocketSession(this))
    , m_updateManager(new QNetworkAccessManager(this)) {
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
        if (currentHost == QStringLiteral("127.0.0.1") || currentHost.startsWith(QStringLiteral("192.168."))) {
            snmpSection.insert(QStringLiteral("host"), QString());
            m_settings->setSection(QStringLiteral("snmp"), snmpSection);
        }
        m_settings->setValue(QStringLiteral("snmp_defaults_v1"), true);
        m_settings->save();
    }
    const bool cleanSessionDefaultsV1Applied = m_settings->value(QStringLiteral("session_defaults_v1"), false).toBool(false);
    if (!cleanSessionDefaultsV1Applied) {
        for (const auto& key : {QStringLiteral("ssh"), QStringLiteral("telnet"), QStringLiteral("tcp"), QStringLiteral("udp")}) {
            QJsonObject section = m_settings->section(key);
            const QString currentHost = section.value(QStringLiteral("host")).toString().trimmed();
            if (currentHost == QStringLiteral("127.0.0.1")) {
                section.insert(QStringLiteral("host"), QString());
                m_settings->setSection(key, section);
            }
        }
        m_settings->setValue(QStringLiteral("session_defaults_v1"), true);
        m_settings->save();
    }
    refreshTerminalFormats();
    const bool vendorDbReady = m_vendorDb->ensureReady(false);
    m_scanAutoScanTimer = new QTimer(this);
    m_scanAutoScanTimer->setSingleShot(false);
    m_scanAutoScanTimer->setInterval(qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)) * 1000);
    m_scanBackgroundRefreshTimer = new QTimer(this);
    m_scanBackgroundRefreshTimer->setSingleShot(true);
    m_scanBackgroundRefreshTimer->setInterval(qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)) * 1000);
#ifndef Q_OS_ANDROID
    m_serialPortRefreshTimer = new QTimer(this);
    m_serialPortRefreshTimer->setSingleShot(false);
    m_serialPortRefreshTimer->setInterval(10000);
#endif
    m_networkMonitorTimer = new QTimer(this);
    m_networkMonitorTimer->setSingleShot(false);
    m_networkMonitorTimer->setInterval(1500);

    qRegisterMetaType<nt::ScanRecord>("nt::ScanRecord");
    qRegisterMetaType<QList<nt::ScanRecord>>("QList<nt::ScanRecord>");
    qRegisterMetaType<nt::HttpResponse>("nt::HttpResponse");

    applyDarkPalette();
    applyStyleSheet();
    buildUi();

    setWindowTitle(localizedWindowTitle(m_settings));
    resize(m_settings->initialWindowSize());
    setMinimumSize(840, 440);
    setMaximumSize(1280, 820);
    setWindowFlag(Qt::WindowMaximizeButtonHint, false);
    statusBar()->hide();
    updateScanFooter(localizedScanIdleText(m_settings));

    connect(m_scanAutoScanTimer, &QTimer::timeout, this, [this]() {
        if (m_scanAutoScanCheck != nullptr
            && m_scanAutoScanCheck->isChecked()
            && m_scanner != nullptr
            && !m_scanner->isRunning()
            && !m_scanLaunchPending) {
            if (scanBackgroundRefreshEnabled() && !m_scanRows.isEmpty()) {
                startScanBackgroundRefresh();
            } else {
                startScan();
            }
        }
    });
    connect(m_scanBackgroundRefreshTimer, &QTimer::timeout, this, [this]() {
        startScanBackgroundRefresh();
    });
#ifndef Q_OS_ANDROID
    connect(m_serialPortRefreshTimer, &QTimer::timeout, this, &MainWindow::refreshSerialPorts);
#endif
    connect(m_networkMonitorTimer, &QTimer::timeout, this, &MainWindow::refreshNetworkMonitoring);
    connect(m_vendorDb, &nt::VendorDbService::statusChanged, this, [this](const QString&, bool available) {
        if (!available || m_scanRows.isEmpty()) {
            return;
        }
        bool changed = false;
        for (auto& row : m_scanRows) {
            if (!isUnknownVendorText(row.vendor)
                || row.mac.trimmed().isEmpty()
                || row.mac == QStringLiteral("-")) {
                continue;
            }
            const QString vendor = m_vendorDb->lookupVendor(row.mac);
            if (!isUnknownVendorText(vendor)) {
                row.vendor = vendor;
                changed = true;
            }
        }
        if (changed) {
            rebuildScanTable();
            updateSelectedHostPanel();
        }
    });
    if (!vendorDbReady && m_settings->value(QStringLiteral("vendor_auto_update"), true).toBool(true)) {
        QPointer<nt::VendorDbService> vendorDb(m_vendorDb);
        QTimer::singleShot(1200, this, [vendorDb]() {
            if (vendorDb == nullptr) {
                return;
            }
            (void)QtConcurrent::run([vendorDb]() {
                if (vendorDb != nullptr) {
                    vendorDb->ensureReady(true);
                }
            });
        });
    }
    const bool autoScanEnabled = m_settings->value(QStringLiteral("auto_scan_enabled"), true).toBool(true);
    const bool scanOnStartup = m_settings->value(QStringLiteral("scan_on_startup"), false).toBool(false);
    if (autoScanEnabled || scanOnStartup) {
        QTimer::singleShot(250, this, [this]() {
            if (m_scanner != nullptr && !m_scanner->isRunning() && !m_scanLaunchPending) {
                startScan();
            }
        });
    }
    QTimer::singleShot(2200, this, [this]() {
        checkForUpdates(true);
    });

    connect(m_scanner, &nt::NetworkScanService::scanStarted, this, [this]() {
        m_scanLaunchPending = false;
        m_scanPolishingActive = false;
        if (m_scanBackgroundRefreshRun) {
            if (m_scanStartButton != nullptr) {
                m_scanStartButton->setEnabled(false);
            }
            updateScanFooter(localizedScanRefreshingText(m_settings));
            return;
        }
        if (m_scanStartButton != nullptr) {
            m_scanStartButton->setText(uiText(m_settings, "■ Стоп", "■ Stop"));
            m_scanStartButton->setEnabled(true);
        }
        if (m_scanStopButton != nullptr) {
            m_scanStopButton->setEnabled(true);
        }
        updateScanFooter(localizedScanScanningText(m_settings));
    });
    connect(m_scanner, &nt::NetworkScanService::recordReady, this, &MainWindow::appendScanRecord);
    connect(m_scanner, &nt::NetworkScanService::scanFinished, this, &MainWindow::finalizeScan);
    connect(m_scanner, &nt::NetworkScanService::scanFailed, this, [this](const QString& errorText) {
        const bool backgroundRefresh = m_scanBackgroundRefreshRun;
        m_scanLaunchPending = false;
        m_scanBackgroundRefreshRun = false;
        m_scanPolishingActive = false;
        appendScanLogLine(QStringLiteral("failed error=%1").arg(errorText));
        if (backgroundRefresh) {
            if (m_scanStartButton != nullptr) {
                m_scanStartButton->setEnabled(true);
                m_scanStartButton->setText(uiText(m_settings, "▶ Старт", "▶ Start"));
            }
            updateScanFooter(uiText(m_settings, "Фоновое обновление не выполнено: %1", "Background refresh failed: %1").arg(localizedRuntimeStatus(m_settings, errorText)));
            updateScanBackgroundRefreshTimer();
            return;
        }
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
        cursor.insertText(statusText.trimmed(), statusFormat);
        cursor.insertBlock();
        cursor.insertText(QStringLiteral("%1 %2").arg(response.method, response.url), textFormat);
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignHCenter);
        cursor.insertText(localizedRequestBodyDivider(), textFormat);
        cursor.insertBlock();

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
        m_requestResponseEdit->setProperty("latest_http_body", text);
        cursor.insertText(uiText(m_settings, "Тело ответа скрыто. Двойной клик по панели раскроет его.", "Response body is hidden. Double-click the panel to expand it."), textFormat);
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignHCenter);
        cursor.insertText(localizedRequestEndDivider(), textFormat);
        cursor.insertBlock();
        cursor.insertBlock();
        setHttpBlockAlignment(Qt::AlignLeft);
        m_requestResponseEdit->setTextCursor(cursor);
        m_requestResponseEdit->ensureCursorVisible();
    });

#ifndef Q_OS_ANDROID
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
#endif

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
    saveScanColumnWidths();
    const QSize savedSize = isMaximized() ? normalGeometry().size() : size();
    m_settings->setSection(QStringLiteral("window"), QJsonObject{
        {QStringLiteral("width"), savedSize.width()},
        {QStringLiteral("height"), savedSize.height()},
        {QStringLiteral("maximized"), false},
    });
    m_settings->save();
    m_scanner->cancel();
    m_sshSession->close();
    m_telnetSession->close();
    QMainWindow::closeEvent(event);
}

bool MainWindow::eventFilter(QObject* object, QEvent* event) {
    if (m_scanTable != nullptr && object == m_scanTable->viewport()) {
        if (event->type() == QEvent::MouseMove) {
            auto* mouseEvent = static_cast<QMouseEvent*>(event);
            maybeShowScanCellHover(mouseEvent->pos());
        } else if (event->type() == QEvent::Resize) {
            QTimer::singleShot(0, this, [this]() { applyScanColumnWidths(); });
        }
        return QMainWindow::eventFilter(object, event);
    }
    if (object == m_requestResponseEdit && event->type() == QEvent::MouseButtonDblClick) {
        const QString body = m_requestResponseEdit != nullptr ? m_requestResponseEdit->property("latest_http_body").toString() : QString();
        if (!body.isEmpty()) {
            QTextCursor cursor(m_requestResponseEdit->document());
            cursor.movePosition(QTextCursor::End);
            QTextCharFormat textFormat;
            textFormat.setFont(fixedFont());
            textFormat.setForeground(isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6"));
            QTextBlockFormat blockFormat = cursor.blockFormat();
            blockFormat.setAlignment(Qt::AlignLeft);
            cursor.setBlockFormat(blockFormat);
            cursor.insertText(body, textFormat);
            cursor.insertBlock();
            cursor.insertBlock();
            m_requestResponseEdit->setProperty("latest_http_body", QString());
            m_requestResponseEdit->setTextCursor(cursor);
            m_requestResponseEdit->ensureCursorVisible();
            return true;
        }
    }
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
            background:#176b3a;
            color:#ffffff;
            border:1px solid #0f4f2a;
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
        QPushButton#textLinkButton { background:transparent; border:none; color:#416f9e; padding:0px 4px; min-height:20px; max-height:20px; font-size:11px; font-weight:500; }
        QPushButton#textLinkButton:hover { background:transparent; border:none; color:#1f5f9f; text-decoration:underline; }
        QPushButton#textLinkButton:pressed { background:transparent; border:none; padding:0px 4px; }
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
        QPushButton#textLinkButton {
            background:transparent;
            border:none;
            color:#8dbff2;
            padding:0px 4px;
            min-height:20px;
            max-height:20px;
            font-size:11px;
            font-weight:500;
        }
        QPushButton#textLinkButton:hover { background:transparent; border:none; color:#b6d7ff; text-decoration:underline; }
        QPushButton#textLinkButton:pressed { background:transparent; border:none; padding:0px 4px; }
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
    m_sshTerminalBaseFormat = defaultTerminalFormat(terminalPresetColor(m_settings->value(QStringLiteral("ssh_terminal_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"))));
    m_telnetTerminalBaseFormat = defaultTerminalFormat(terminalPresetColor(m_settings->value(QStringLiteral("telnet_terminal_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"))));
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
            && scanIpFromItem(ipItem) == gatewayItem->text();
        for (int col = 0; col < m_scanTable->columnCount(); ++col) {
            auto* item = m_scanTable->item(row, col);
            if (item == nullptr) {
                continue;
            }
            QColor cellBackground = isGatewayHost ? gatewayBackground : defaultBackground;
            QColor cellForeground = isGatewayHost ? gatewayForeground : defaultForeground;
            if (col == ScanColumnPing
                && m_settings != nullptr
                && m_settings->value(QStringLiteral("scan_ping_health_colors"), false).toBool(false)) {
                pingHealthBrushes(item->text(), &cellBackground, &cellForeground);
            }
            item->setBackground(QBrush(cellBackground));
            item->setForeground(QBrush(cellForeground));
            QFont font = item->font();
            font.setBold(isGatewayHost);
            item->setFont(font);
        }
    }
    m_scanTable->viewport()->update();
}
