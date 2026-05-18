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
#ifndef Q_OS_ANDROID
        QStringLiteral("Serial"),
#endif
        QStringLiteral("TCP"),
        QStringLiteral("UDP"),
        QStringLiteral("SSH"),
        QStringLiteral("Telnet"),
        QStringLiteral("SNMP Browser"),
        uiText(language, "Поиск портов", "Search Ports"),
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
    m_scanAutoScanCheck->setChecked(m_settings->value(QStringLiteral("auto_scan_enabled"), true).toBool(true));
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

    m_scanProfileMenu = new QMenu(toolbar);
    auto* scanProfileGroup = new QActionGroup(m_scanProfileMenu);
    scanProfileGroup->setExclusive(true);
    const QStringList scanProfiles {
        QStringLiteral("fast"),
        QStringLiteral("balanced"),
        QStringLiteral("reliable"),
    };
    for (const auto& profile : scanProfiles) {
        auto* action = m_scanProfileMenu->addAction(scanProfileTitle(m_settings, profile));
        action->setCheckable(true);
        action->setActionGroup(scanProfileGroup);
        action->setToolTip(scanProfileDescription(m_settings, profile));
        action->setChecked(normalizedScanProfileForUi(m_settings->scanProfile()) == profile);
        connect(action, &QAction::triggered, this, [this, profile]() {
            setScanProfile(profile);
        });
        m_scanProfileActions.insert(profile, action);
    }
    m_scanProfileMenu->setTitle(uiText(language, "Режим скана", "Scan mode"));

    m_scanProfileButton = new QToolButton(toolbar);
    m_scanProfileButton->setObjectName(QStringLiteral("scanGearButton"));
    m_scanProfileButton->setAutoRaise(true);
    m_scanProfileButton->setPopupMode(QToolButton::InstantPopup);
    m_scanProfileButton->setMenu(m_scanProfileMenu);
    optionsRow->addWidget(m_scanProfileButton);

    m_scanPingHealthButton = new QToolButton(toolbar);
    m_scanPingHealthButton->setObjectName(QStringLiteral("scanGearButton"));
    m_scanPingHealthButton->setAutoRaise(true);
    m_scanPingHealthButton->setCheckable(true);
    m_scanPingHealthButton->setChecked(m_settings->value(QStringLiteral("scan_ping_health_colors"), false).toBool(false));
    optionsRow->addWidget(m_scanPingHealthButton);

    optionsRow->addStretch(1);
    toolbarLayout->addLayout(optionsRow);

    m_scanOnlineLabel = new QLabel(uiText(language, "Онлайн: 0", "Online: 0"), toolbar);
    m_scanOnlineLabel->hide();
    m_scanStopButton = new QPushButton(page);
    m_scanStopButton->hide();

    connect(m_scanStartButton, &QPushButton::clicked, this, [this]() {
        if (m_scanner != nullptr && (m_scanner->isRunning() || m_scanLaunchPending) && !m_scanStopRequested) {
            stopScan();
        } else if (m_scanner != nullptr && m_scanner->isRunning() && m_scanStopRequested) {
            m_scanRestartAfterStop = true;
            updateScanFooter(uiText(m_settings, "Скан останавливается, новый запуск начнется сразу после остановки.", "Stopping scan; restart will begin immediately."));
            QTimer::singleShot(160, this, [this]() {
                if (!m_scanRestartAfterStop) {
                    return;
                }
                if (m_scanner != nullptr && m_scanner->isRunning()) {
                    QTimer::singleShot(160, this, [this]() {
                        if (m_scanRestartAfterStop && m_scanner != nullptr && !m_scanner->isRunning()) {
                            m_scanRestartAfterStop = false;
                            startScan();
                        }
                    });
                    return;
                }
                m_scanRestartAfterStop = false;
                startScan();
            });
        } else {
            startScan();
        }
    });
    connect(m_scanStopButton, &QPushButton::clicked, this, &MainWindow::stopScan);
    connect(m_scanSortButton, &QPushButton::clicked, this, &MainWindow::toggleScanSortOrder);
    connect(m_scanPingHealthButton, &QToolButton::toggled, this, &MainWindow::setScanPingHealthColors);
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
            if (m_scanAutoScanTimer != nullptr) {
                m_scanAutoScanTimer->start();
            }
            updateScanFooter(uiText(m_settings, "Авто скан включен", "Auto scan enabled"));
            if (m_scanner != nullptr && !m_scanner->isRunning() && !m_scanLaunchPending) {
                if (scanBackgroundRefreshEnabled() && !m_scanRows.isEmpty()) {
                    startScanBackgroundRefresh();
                } else {
                    startScan();
                }
            }
        } else {
            if (m_scanAutoScanTimer != nullptr) {
                m_scanAutoScanTimer->stop();
            }
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
    m_scanTable->setMouseTracking(true);
    m_scanTable->viewport()->setMouseTracking(true);
    m_scanTable->viewport()->installEventFilter(this);
    m_scanTable->verticalHeader()->setVisible(false);
    m_scanTable->verticalHeader()->setDefaultSectionSize(23);
    m_scanTable->horizontalHeader()->setFixedHeight(23);
    m_scanTable->horizontalHeader()->setStretchLastSection(false);
    m_scanTable->horizontalHeader()->setMinimumSectionSize(44);
    for (int column = 0; column < ScanColumnCount; ++column) {
        m_scanTable->horizontalHeader()->setSectionResizeMode(column, QHeaderView::Interactive);
    }
    m_scanTable->setShowGrid(true);
    for (int column = 0; column < ScanColumnCount; ++column) {
        m_scanTable->setColumnWidth(column, defaultScanColumnWidth(column));
    }
    applyScanColumnWidths();
    m_scanColumnWidthSaveTimer = new QTimer(this);
    m_scanColumnWidthSaveTimer->setSingleShot(true);
    m_scanColumnWidthSaveTimer->setInterval(220);
    connect(m_scanColumnWidthSaveTimer, &QTimer::timeout, this, &MainWindow::saveScanColumnWidths);
    connect(m_scanTable->horizontalHeader(), &QHeaderView::sectionResized, this, [this](int, int, int) {
        if (m_scanColumnWidthSaveTimer != nullptr) {
            m_scanColumnWidthSaveTimer->start();
        }
    });
    connect(m_scanTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::updateSelectedHostPanel);
    connect(m_scanTable, &QTableWidget::cellClicked, this, &MainWindow::showScanCellDetails);
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
    applyScanColumnWidths();
    updateScanSortButton();
    refreshScanToolbarIcons();
    if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()) {
        m_scanAutoScanTimer->start();
    }
    updateScanBackgroundRefreshTimer();
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
    m_requestResponseEdit->installEventFilter(this);
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

#ifndef Q_OS_ANDROID
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
    topLayout->addWidget(m_serialWidgets.connectButton, 1, 7);
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
    auto* inputLabel = new QLabel(uiText(language, "Ввод", "Input"), sendBox);
    inputLabel->hide();
    m_serialWidgets.inputEdit->hide();
    sendButton->hide();
    sendLayout->addWidget(inputLabel, 0, 0);
    sendLayout->addWidget(m_serialWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 4; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
        m_serialWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(uiText(language, "Команда %1", "Cmd %1").arg(i + 1), sendBox), i + 1, 0);
        sendLayout->addWidget(quickEdit, i + 1, 1);
        sendLayout->addWidget(quickButton, i + 1, 2);
        connect(quickEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
        connect(quickButton, &QPushButton::clicked, this, [this, i]() { sendQuickCommand(QStringLiteral("serial"), m_serialWidgets, i); });
    }
    root->addWidget(sendBox);

    connect(m_serialWidgets.connectButton, &QPushButton::clicked, this, &MainWindow::toggleSerial);
    connect(sendButton, &QPushButton::clicked, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::returnPressed, this, &MainWindow::sendSerialPayload);
    connect(m_serialWidgets.inputEdit, &QLineEdit::textChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });
    connect(m_serialWidgets.eolCombo, &QComboBox::currentTextChanged, this, [this]() { saveQuickCommands(QStringLiteral("serial"), m_serialWidgets); });

    refreshSerialPorts();
    if (m_serialPortRefreshTimer != nullptr && !m_serialPortRefreshTimer->isActive()) {
        m_serialPortRefreshTimer->start();
    }
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
#endif

QWidget* MainWindow::createTcpPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(4, 4, 4, 4);
    root->setSpacing(4);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(6, 4, 6, 4);
    topLayout->setHorizontalSpacing(5);
    topLayout->setVerticalSpacing(3);

    m_tcpWidgets.hostEdit = new QLineEdit(top);
    m_tcpWidgets.hostEdit->setPlaceholderText(uiText(language, "IP / хост", "IP / host"));
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
    m_tcpWidgets.autoPortCheck = new QCheckBox(uiText(language, "Автопорт", "Auto port"), top);
    m_tcpWidgets.connectButton = new QPushButton(uiText(language, "Подключить", "Connect"), top);

    topLayout->addWidget(new QLabel(uiText(language, "Хост", "Host"), top), 0, 0);
    topLayout->addWidget(m_tcpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Удаленный порт", "Remote port"), top), 0, 2);
    topLayout->addWidget(m_tcpWidgets.portSpin, 0, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Локальный порт", "Local port"), top), 0, 4);
    topLayout->addWidget(m_tcpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_tcpWidgets.connectButton, 0, 6);
    topLayout->addWidget(new QLabel(uiText(language, "Окончание", "Line ending"), top), 1, 0);
    topLayout->addWidget(m_tcpWidgets.eolCombo, 1, 1);
    topLayout->addWidget(m_tcpWidgets.noDelayCheck, 1, 2);
    topLayout->addWidget(m_tcpWidgets.keepAliveCheck, 1, 3);
    topLayout->addWidget(m_tcpWidgets.autoPortCheck, 1, 4);
    topLayout->addWidget(m_tcpWidgets.hexCheck, 1, 5);
    topLayout->setColumnStretch(1, 1);
    topLayout->setColumnStretch(6, 0);
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
    auto* inputLabel = new QLabel(uiText(language, "Ввод", "Input"), sendBox);
    inputLabel->hide();
    m_tcpWidgets.inputEdit->hide();
    sendButton->hide();
    sendLayout->addWidget(inputLabel, 0, 0);
    sendLayout->addWidget(m_tcpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 4; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
        m_tcpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(uiText(language, "Команда %1", "Cmd %1").arg(i + 1), sendBox), i + 1, 0);
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
    connect(m_tcpWidgets.autoPortCheck, &QCheckBox::toggled, this, [this](bool checked) {
        auto section = m_settings->section(QStringLiteral("tcp"));
        section.insert(QStringLiteral("auto_port"), checked);
        m_settings->setSection(QStringLiteral("tcp"), section);
        m_settings->save();
    });
    {
        const auto section = m_settings->section(QStringLiteral("tcp"));
        m_tcpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString());
        m_tcpWidgets.portSpin->setValue(section.value(QStringLiteral("port")).toInt(23));
        m_tcpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_tcpWidgets.noDelayCheck->setChecked(section.value(QStringLiteral("no_delay")).toBool(true));
        m_tcpWidgets.keepAliveCheck->setChecked(section.value(QStringLiteral("keep_alive")).toBool(false));
        m_tcpWidgets.autoPortCheck->setChecked(section.value(QStringLiteral("auto_port")).toBool(false));
        setComboByData(m_tcpWidgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
    loadQuickCommands(QStringLiteral("tcp"), m_tcpWidgets);
    return page;
}

QWidget* MainWindow::createUdpPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(4, 4, 4, 4);
    root->setSpacing(4);

    auto* top = new QFrame(page);
    top->setObjectName(QStringLiteral("toolbarPanel"));
    auto* topLayout = new QGridLayout(top);
    topLayout->setContentsMargins(6, 4, 6, 4);
    topLayout->setHorizontalSpacing(5);
    topLayout->setVerticalSpacing(3);

    m_udpWidgets.hostEdit = new QLineEdit(top);
    m_udpWidgets.hostEdit->setPlaceholderText(uiText(language, "IP / хост", "IP / host"));
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
    m_udpWidgets.autoPortCheck = new QCheckBox(uiText(language, "Автопорт", "Auto port"), top);
    m_udpWidgets.connectButton = new QPushButton(uiText(language, "Открыть", "Open"), top);

    topLayout->addWidget(new QLabel(uiText(language, "Удаленный хост", "Remote host"), top), 0, 0);
    topLayout->addWidget(m_udpWidgets.hostEdit, 0, 1);
    topLayout->addWidget(new QLabel(uiText(language, "Удаленный порт", "Remote port"), top), 0, 2);
    topLayout->addWidget(m_udpWidgets.remotePortSpin, 0, 3);
    topLayout->addWidget(new QLabel(uiText(language, "Локальный порт", "Local port"), top), 0, 4);
    topLayout->addWidget(m_udpWidgets.localPortSpin, 0, 5);
    topLayout->addWidget(m_udpWidgets.connectButton, 0, 6);
    topLayout->addWidget(new QLabel(uiText(language, "Окончание", "Line ending"), top), 1, 0);
    topLayout->addWidget(m_udpWidgets.eolCombo, 1, 1);
    topLayout->addWidget(m_udpWidgets.reuseAddressCheck, 1, 2);
    topLayout->addWidget(m_udpWidgets.autoPortCheck, 1, 3);
    topLayout->addWidget(m_udpWidgets.hexCheck, 1, 4);
    topLayout->setColumnStretch(1, 1);
    topLayout->setColumnStretch(6, 0);
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
    auto* inputLabel = new QLabel(uiText(language, "Ввод", "Input"), sendBox);
    inputLabel->hide();
    m_udpWidgets.inputEdit->hide();
    sendButton->hide();
    sendLayout->addWidget(inputLabel, 0, 0);
    sendLayout->addWidget(m_udpWidgets.inputEdit, 0, 1);
    sendLayout->addWidget(sendButton, 0, 2);
    for (int i = 0; i < 4; ++i) {
        auto* quickEdit = new QLineEdit(sendBox);
        quickEdit->setPlaceholderText(uiText(language, "Команда %1", "Command %1").arg(i + 1));
        auto* quickButton = new QPushButton(uiText(language, "Отправить", "Send"), sendBox);
        m_udpWidgets.quickEdits.append(quickEdit);
        sendLayout->addWidget(new QLabel(uiText(language, "Команда %1", "Cmd %1").arg(i + 1), sendBox), i + 1, 0);
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
    connect(m_udpWidgets.autoPortCheck, &QCheckBox::toggled, this, [this](bool checked) {
        auto section = m_settings->section(QStringLiteral("udp"));
        section.insert(QStringLiteral("auto_port"), checked);
        m_settings->setSection(QStringLiteral("udp"), section);
        m_settings->save();
    });
    {
        const auto section = m_settings->section(QStringLiteral("udp"));
        m_udpWidgets.hostEdit->setText(section.value(QStringLiteral("host")).toString());
        m_udpWidgets.remotePortSpin->setValue(section.value(QStringLiteral("remote_port")).toInt(52381));
        m_udpWidgets.localPortSpin->setValue(section.value(QStringLiteral("local_port")).toInt(0));
        m_udpWidgets.reuseAddressCheck->setChecked(section.value(QStringLiteral("reuse_address")).toBool(true));
        m_udpWidgets.autoPortCheck->setChecked(section.value(QStringLiteral("auto_port")).toBool(false));
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
    left->setMinimumWidth(190);
    left->setMaximumWidth(250);
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
    auto* settingsButton = new QToolButton(portRow);
    settingsButton->setObjectName(QStringLiteral("scanGearButton"));
    settingsButton->setAutoRaise(true);
    settingsButton->setIcon(scanGearIcon(isLightTheme() ? QColor("#5f6a76") : QColor("#c1ccd8")));
    settingsButton->setIconSize(QSize(18, 18));
    settingsButton->setToolTip(uiText(language, "Настройки терминала", "Terminal settings"));
    portLayout->addWidget(settingsButton);
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
    splitter->setSizes({220, 1020});

    connect(newButton, &QPushButton::clicked, this, [this, &widgets, defaultPort]() { newSessionProfile(widgets, defaultPort); });
    connect(deleteButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { deleteSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(widgets.saveButton, &QPushButton::clicked, this, [this, kind, &widgets, defaultPort]() { saveSessionProfile(kind.toLower(), widgets, defaultPort); });
    connect(settingsButton, &QToolButton::clicked, this, [this, kind, &widgets]() { openSessionSettings(kind.toLower(), widgets); });
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
    m_snmpWidgets.communityLoadButton = new QPushButton(uiText(language, "Опросить все OID", "Walk all OIDs"), toolbar);
    m_snmpWidgets.communityLoadButton->setObjectName(QStringLiteral("scanStartButton"));

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
    m_snmpWidgets.communityLoadButton->setFixedHeight(19);
    m_snmpWidgets.communityLoadButton->setFixedWidth(118);

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
    communityLayout->addWidget(m_snmpWidgets.communityLoadButton);
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
    v3Row2->addWidget(m_snmpWidgets.loadButton);
    v3Layout->addLayout(v3Row1);
    v3Layout->addLayout(v3Row2);
    m_snmpWidgets.securityStack->addWidget(v3Page);
    auto* securityRow = new QHBoxLayout();
    securityRow->setContentsMargins(0, 0, 0, 0);
    securityRow->setSpacing(5);
    securityRow->addWidget(m_snmpWidgets.securityStack, 0, Qt::AlignLeft);
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
    connect(m_snmpWidgets.communityLoadButton, &QPushButton::clicked, this, &MainWindow::loadSnmpOidList);
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

QWidget* MainWindow::createSearchPortsPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(8);

    auto* toolbar = new QFrame(page);
    toolbar->setObjectName(QStringLiteral("toolbarPanel"));
    auto* toolbarLayout = new QGridLayout(toolbar);
    toolbarLayout->setContentsMargins(8, 6, 8, 6);
    toolbarLayout->setSpacing(6);
    toolbarLayout->addWidget(new QLabel(QStringLiteral("IP"), toolbar), 0, 0);
    m_portSearchHostEdit = new QLineEdit(toolbar);
    m_portSearchHostEdit->setPlaceholderText(QStringLiteral("192.168.0.1"));
    m_portSearchHostEdit->setFixedWidth(168);
    toolbarLayout->addWidget(m_portSearchHostEdit, 0, 1);
    m_portSearchButton = new QPushButton(uiText(language, "Сканировать порты", "Scan ports"), toolbar);
    m_portSearchButton->setFixedWidth(132);
    toolbarLayout->addWidget(m_portSearchButton, 0, 2);
    auto* orLabel = new QLabel(uiText(language, "или диапазон", "or range"), toolbar);
    orLabel->setAlignment(Qt::AlignCenter);
    toolbarLayout->addWidget(orLabel, 0, 3);
    m_portSearchRangeStartEdit = new QLineEdit(toolbar);
    m_portSearchRangeStartEdit->setPlaceholderText(QStringLiteral("192.168.0.1"));
    m_portSearchRangeStartEdit->setFixedWidth(132);
    toolbarLayout->addWidget(m_portSearchRangeStartEdit, 0, 4);
    toolbarLayout->addWidget(new QLabel(QStringLiteral("-"), toolbar), 0, 5);
    m_portSearchRangeEndEdit = new QLineEdit(toolbar);
    m_portSearchRangeEndEdit->setPlaceholderText(QStringLiteral("192.168.0.50"));
    m_portSearchRangeEndEdit->setFixedWidth(132);
    toolbarLayout->addWidget(m_portSearchRangeEndEdit, 0, 6);
    m_portSearchRangeButton = new QPushButton(uiText(language, "Сканировать диапазон", "Scan range"), toolbar);
    m_portSearchRangeButton->setFixedWidth(142);
    toolbarLayout->addWidget(m_portSearchRangeButton, 0, 7);
    toolbarLayout->setColumnStretch(8, 1);
    m_portSearchStatusLabel = new QLabel(toolbar);
    m_portSearchStatusLabel->setObjectName(QStringLiteral("statusHint"));
    m_portSearchStatusLabel->hide();
    root->addWidget(toolbar, 0);

    m_portSearchTable = new QTableWidget(0, 5, page);
    m_portSearchTable->setHorizontalHeaderLabels({
        QStringLiteral("IP"),
        QStringLiteral("MAC"),
        uiText(language, "Порты", "Ports"),
        uiText(language, "Сервисы", "Services"),
        uiText(language, "Ответ", "Response"),
    });
    m_portSearchTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_portSearchTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_portSearchTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_portSearchTable->verticalHeader()->setVisible(false);
    m_portSearchTable->horizontalHeader()->setStretchLastSection(true);
    m_portSearchTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    m_portSearchTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    m_portSearchTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_portSearchTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_portSearchTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_portSearchTable->setColumnWidth(0, 132);
    m_portSearchTable->setColumnWidth(1, 132);
    m_portSearchTable->setColumnWidth(2, 170);
    m_portSearchTable->setColumnWidth(4, 120);
    root->addWidget(m_portSearchTable, 1);

    connect(m_portSearchButton, &QPushButton::clicked, this, &MainWindow::runPortSearch);
    connect(m_portSearchHostEdit, &QLineEdit::returnPressed, this, &MainWindow::runPortSearch);
    connect(m_portSearchRangeButton, &QPushButton::clicked, this, [this]() {
        if (m_portSearchHostEdit == nullptr || m_portSearchRangeStartEdit == nullptr || m_portSearchRangeEndEdit == nullptr) {
            return;
        }
        setProperty("port_search_input", QStringLiteral("%1-%2").arg(m_portSearchRangeStartEdit->text().trimmed(), m_portSearchRangeEndEdit->text().trimmed()));
        runPortSearch();
    });
    connect(m_portSearchRangeStartEdit, &QLineEdit::returnPressed, m_portSearchRangeButton, &QPushButton::click);
    connect(m_portSearchRangeEndEdit, &QLineEdit::returnPressed, m_portSearchRangeButton, &QPushButton::click);
    return page;
}

QWidget* MainWindow::createNetworkMonitoringPage() {
    const QString language = m_settings->language();
    auto* page = new QWidget(this);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(8);

    auto* toolbar = new QFrame(page);
    toolbar->setObjectName(QStringLiteral("toolbarPanel"));
    auto* toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(8, 6, 8, 6);
    toolbarLayout->setSpacing(6);
    m_networkMonitorToggleButton = new QPushButton(uiText(language, "Старт", "Start"), toolbar);
    toolbarLayout->addWidget(m_networkMonitorToggleButton);
    m_networkMonitorStatusLabel = new QLabel(uiText(language, "Активные TCP/UDP соединения ОС. Payload требует Npcap/libpcap.", "Active OS TCP/UDP connections. Payload capture requires Npcap/libpcap."), toolbar);
    m_networkMonitorStatusLabel->setObjectName(QStringLiteral("statusHint"));
    toolbarLayout->addWidget(m_networkMonitorStatusLabel, 1);
    root->addWidget(toolbar, 0);

    auto* splitter = new QSplitter(Qt::Vertical, page);
    m_networkMonitorTable = new QTableWidget(0, 6, splitter);
    m_networkMonitorTable->setHorizontalHeaderLabels({QStringLiteral("Proto"), QStringLiteral("Local"), QStringLiteral("Remote"), QStringLiteral("State"), QStringLiteral("PID"), QStringLiteral("Direction")});
    m_networkMonitorTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_networkMonitorTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_networkMonitorTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_networkMonitorTable->verticalHeader()->setVisible(false);
    m_networkMonitorTable->horizontalHeader()->setStretchLastSection(true);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_networkMonitorTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    splitter->addWidget(m_networkMonitorTable);
    m_networkMonitorDetails = new QTextEdit(splitter);
    m_networkMonitorDetails->setReadOnly(true);
    m_networkMonitorDetails->setFont(fixedFont());
    splitter->addWidget(m_networkMonitorDetails);
    splitter->setSizes({520, 160});
    root->addWidget(splitter, 1);

    connect(m_networkMonitorToggleButton, &QPushButton::clicked, this, [this]() {
        if (m_networkMonitorTimer == nullptr) {
            return;
        }
        if (m_networkMonitorTimer->isActive()) {
            m_networkMonitorTimer->stop();
            m_networkMonitorToggleButton->setText(uiText(m_settings, "Старт", "Start"));
            return;
        }
        refreshNetworkMonitoring();
        m_networkMonitorTimer->start();
        m_networkMonitorToggleButton->setText(uiText(m_settings, "Стоп", "Stop"));
    });
    connect(m_networkMonitorTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (m_networkMonitorTable == nullptr || m_networkMonitorDetails == nullptr || m_networkMonitorTable->currentRow() < 0) {
            return;
        }
        QStringList lines;
        for (int column = 0; column < m_networkMonitorTable->columnCount(); ++column) {
            const auto* header = m_networkMonitorTable->horizontalHeaderItem(column);
            const auto* item = m_networkMonitorTable->item(m_networkMonitorTable->currentRow(), column);
            lines.append(QStringLiteral("%1: %2").arg(header != nullptr ? header->text() : QString(), item != nullptr ? item->text() : QString()));
        }
        m_networkMonitorDetails->setPlainText(lines.join(QLatin1Char('\n')));
    });
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
#ifndef Q_OS_ANDROID
        {QStringLiteral("Serial"), 2},
        {QStringLiteral("TCP"), 3},
        {QStringLiteral("UDP"), 4},
        {QStringLiteral("SSH"), 5},
        {QStringLiteral("Telnet"), 6},
        {QStringLiteral("SNMP Browser"), 7},
        {uiText(language, "Поиск портов", "Search Ports"), 8},
#else
        {QStringLiteral("TCP"), 2},
        {QStringLiteral("UDP"), 3},
        {QStringLiteral("SSH"), 4},
        {QStringLiteral("Telnet"), 5},
        {QStringLiteral("SNMP Browser"), 6},
        {uiText(language, "Поиск портов", "Search Ports"), 7},
#endif
    };
    for (const auto& item : pages) {
        goToMenu->addAction(item.first, this, [this, index = item.second]() { syncCurrentPage(index); });
    }

    m_favoritesMenu = mainMenu->addMenu(uiText(language, "Анализ сети", "Network Analysis"));
    refreshFavoritesMenu();

    mainMenu->addAction(uiText(language, "Настройки", "Settings"), this, &MainWindow::openSettingsDialog);

    auto* helpMenu = mainMenu->addMenu(uiText(language, "Помощь и обновления", "Help and Updates"));
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
    helpMenu->addAction(uiText(language, "Проверить обновления", "Check for updates"), this, [this]() {
        showUpdateDialog(false);
    });
}
