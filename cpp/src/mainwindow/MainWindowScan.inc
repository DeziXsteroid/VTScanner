void MainWindow::buildUi() {
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    configureMenuBar();

    m_pages = new QStackedWidget(central);
    m_pages->addWidget(createScanPage());
    m_pages->addWidget(createRequestPage());
    m_pages->addWidget(createSerialPage());
    m_pages->addWidget(createTcpPage());
    m_pages->addWidget(createUdpPage());
    m_pages->addWidget(createSessionPage(QStringLiteral("SSH"), m_sshWidgets, 22));
    m_pages->addWidget(createSessionPage(QStringLiteral("Telnet"), m_telnetWidgets, 23));
    m_pages->addWidget(createSnmpPage());
    root->addWidget(m_pages, 1);
    setCentralWidget(central);
    syncCurrentPage(0);
    refreshScanToolbarIcons();
    updateScanSortButton();

    connect(m_sshWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_sshSession->isConnected()) {
            m_sshSession->close();
            return;
        }
        m_sshWidgets.outputBox->clear();
        m_sshSession->open(currentSessionProfile(m_sshWidgets, 22));
    });
    connect(m_telnetWidgets.connectButton, &QPushButton::clicked, this, [this]() {
        if (m_telnetSession->isConnected()) {
            m_telnetSession->close();
            return;
        }
        m_telnetWidgets.outputBox->clear();
        m_telnetSession->open(currentSessionProfile(m_telnetWidgets, 23));
    });
}

void MainWindow::syncCurrentPage(int row) {
    if (m_pages == nullptr || row < 0 || row >= m_pages->count()) {
        return;
    }
    m_pages->setCurrentIndex(row);
}

void MainWindow::openSettingsDialog() {
    const QString previousTheme = m_settings->theme();
    const QString previousLanguage = m_settings->language();
    const QString previousTerminalColor = m_settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"));
    const int previousAutoScanInterval = qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30));
    const bool previousBackgroundRefresh = scanBackgroundRefreshEnabled();
    SettingsDialog dialog(m_settings, this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    updateScanProfileButton();
    if (previousTheme != m_settings->theme()) {
        applyDarkPalette();
        applyStyleSheet();
        refreshScanTableColors();
        refreshScanToolbarIcons();
    }
    if (previousLanguage != m_settings->language()) {
        QMessageBox::information(
            this,
            uiText(m_settings, "Настройки", "Settings"),
            uiText(m_settings, "Язык интерфейса сохранен. Перезапустите приложение.", "Interface language saved. Restart the application.")
        );
    }
    if (previousTerminalColor != m_settings->value(QStringLiteral("terminal_text_color"), QStringLiteral("mint")).toString(QStringLiteral("mint"))) {
        refreshTerminalFormats();
    }
    const int updatedAutoScanInterval = qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30));
    if (previousAutoScanInterval != updatedAutoScanInterval && m_scanAutoScanTimer != nullptr) {
        m_scanAutoScanTimer->setInterval(updatedAutoScanInterval * 1000);
        if (m_scanBackgroundRefreshTimer != nullptr) {
            m_scanBackgroundRefreshTimer->setInterval(updatedAutoScanInterval * 1000);
        }
        if (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked() && !m_scanAutoScanTimer->isActive()) {
            m_scanAutoScanTimer->start();
        }
    }
    if (previousBackgroundRefresh != scanBackgroundRefreshEnabled() || previousAutoScanInterval != updatedAutoScanInterval) {
        updateScanBackgroundRefreshTimer();
    }
}

void MainWindow::reloadAdapters() {
    const auto list = m_scanner->adapters();
    const auto previous = m_scanAdapterCombo->currentData().toString();
    m_scanAdapterCombo->clear();
    for (const auto& adapter : list) {
        const auto range = rangeFromIpAndPrefix(adapter.ip, adapter.prefixLength);
        const QString label = QStringLiteral("%1 | %2").arg(adapter.name, adapter.network);
        m_scanAdapterCombo->addItem(label, adapter.id);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.first, Qt::UserRole + 1);
        m_scanAdapterCombo->setItemData(m_scanAdapterCombo->count() - 1, range.second, Qt::UserRole + 2);
    }
    const int previousIndex = m_scanAdapterCombo->findData(previous);
    if (previousIndex >= 0) {
        m_scanAdapterCombo->setCurrentIndex(previousIndex);
    }
}

void MainWindow::applySuggestedRange() {
    const auto suggestion = m_scanner->suggestRange();
    const int index = m_scanAdapterCombo->findData(suggestion.adapterId);
    if (index >= 0) {
        m_scanAdapterCombo->setCurrentIndex(index);
    }
    if (m_scanAutoIpCheck != nullptr) {
        m_scanAutoIpCheck->setChecked(true);
    }
    if (m_scanAdapterCombo != nullptr && m_scanAdapterCombo->currentIndex() >= 0) {
        applyRangeFromCurrentAdapter();
    } else {
        m_scanStartIp->setText(suggestion.startIp);
        m_scanEndIp->setText(suggestion.endIp);
    }
    updateScanFooter(suggestion.label);
}

void MainWindow::applyRangeFromCurrentAdapter() {
    if (m_scanAdapterCombo == nullptr || m_scanAdapterCombo->currentIndex() < 0) {
        return;
    }
    nt::AdapterInfo adapter;
    const QString adapterId = m_scanAdapterCombo->currentData().toString();
    for (const auto& item : m_scanner->adapters()) {
        if (item.id == adapterId || item.name == adapterId) {
            adapter = item;
            break;
        }
    }
    if (adapter.ip.isEmpty()) {
        return;
    }
    bool ok = false;
    const QString prefixText = m_scanPrefixCombo != nullptr ? m_scanPrefixCombo->currentText() : QStringLiteral("/24");
    const int prefix = prefixText.mid(1).toInt(&ok);
    const auto range = rangeFromIpAndPrefix(adapter.ip, ok ? prefix : qMax(1, adapter.prefixLength));
    if (!range.first.isEmpty()) {
        m_scanStartIp->setText(range.first);
    }
    if (!range.second.isEmpty()) {
        m_scanEndIp->setText(range.second);
    }
}

void MainWindow::resolveHostnameRange() {
    applyRangeFromCurrentAdapter();
    updateScanFooter(uiText(m_settings, "Диапазон обновлен по адаптеру", "Range refreshed from adapter"));
}

bool MainWindow::scanBackgroundRefreshEnabled() const {
    return m_settings != nullptr
        && m_settings->value(QStringLiteral("scan_background_refresh"), false).toBool(false);
}

void MainWindow::updateScanBackgroundRefreshTimer() {
    if (m_scanBackgroundRefreshTimer == nullptr) {
        return;
    }
    m_scanBackgroundRefreshTimer->stop();
    if (!scanBackgroundRefreshEnabled()) {
        if (m_scanBackgroundRefreshRun && m_scanner != nullptr && m_scanner->isRunning()) {
            ++m_currentScanGeneration;
            m_scanBackgroundRefreshRun = false;
            m_scanner->cancel();
            if (m_scanStartButton != nullptr) {
                m_scanStartButton->setEnabled(true);
                m_scanStartButton->setText(uiText(m_settings, "▶ Старт", "▶ Start"));
            }
            updateScanFooter(uiText(m_settings, "Фоновое обновление выключено", "Background refresh disabled"));
        }
        return;
    }
    if (m_scanner == nullptr
        || m_scanner->isRunning()
        || m_scanRows.isEmpty()
        || m_scanLaunchPending) {
        return;
    }
    const int intervalMs = qMax(5, m_settings->value(QStringLiteral("auto_scan_interval_sec"), 30).toInt(30)) * 1000;
    m_scanBackgroundRefreshTimer->setInterval(intervalMs);
    m_scanBackgroundRefreshTimer->start();
}

void MainWindow::startScanBackgroundRefresh() {
    if (!scanBackgroundRefreshEnabled()
        || m_scanner == nullptr
        || m_scanner->isRunning()
        || m_scanRows.isEmpty()
        || m_scanLaunchPending
        || m_scanStartIp == nullptr
        || m_scanEndIp == nullptr
        || m_scanAdapterCombo == nullptr) {
        updateScanBackgroundRefreshTimer();
        return;
    }

    m_scanLaunchPending = true;
    ++m_currentScanGeneration;
    m_scanBackgroundRefreshRun = true;
    m_scanPolishingActive = false;
    if (m_scanAutoIpCheck != nullptr
        && m_scanAutoIpCheck->isChecked()
        && !m_settings->value(QStringLiteral("scan_routed_ranges"), false).toBool(false)) {
        applyRangeFromCurrentAdapter();
    }

    const QString scanProfile = m_settings->scanProfile();
    const bool autoWorkers = m_settings->value(QStringLiteral("scan_auto_workers"), true).toBool(true);
    const int scanWorkers = autoWorkers ? autoScanWorkerCountForProfile(scanProfile) : m_settings->scanWorkers();
    appendScanLogLine(QStringLiteral("background_refresh_start range=%1-%2 adapter=%3 profile=%4 workers=%5")
        .arg(m_scanStartIp != nullptr ? m_scanStartIp->text().trimmed() : QString())
        .arg(m_scanEndIp != nullptr ? m_scanEndIp->text().trimmed() : QString())
        .arg(m_scanAdapterCombo != nullptr ? m_scanAdapterCombo->currentData().toString() : QString())
        .arg(scanProfile)
        .arg(scanWorkers));

    m_scanner->start(
        m_scanStartIp->text().trimmed(),
        m_scanEndIp->text().trimmed(),
        m_scanAdapterCombo->currentData().toString(),
        scanWorkers,
        scanProfile,
        m_currentScanGeneration
    );
}

void MainWindow::startScan() {
    if (m_scanner == nullptr
        || m_scanner->isRunning()
        || m_scanLaunchPending
        || m_scanStartIp == nullptr
        || m_scanEndIp == nullptr
        || m_scanAdapterCombo == nullptr) {
        return;
    }
    m_scanLaunchPending = true;
    if (m_scanBackgroundRefreshTimer != nullptr) {
        m_scanBackgroundRefreshTimer->stop();
    }
    syncCurrentPage(0);
    ++m_currentScanGeneration;
    m_scanBackgroundRefreshRun = false;
    m_scanPolishingActive = false;
    const QString scanProfile = m_settings->scanProfile();
    const bool autoWorkers = m_settings->value(QStringLiteral("scan_auto_workers"), true).toBool(true);
    const int scanWorkers = autoWorkers ? autoScanWorkerCountForProfile(scanProfile) : m_settings->scanWorkers();
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->setText(uiText(m_settings, "■ Стоп", "■ Stop"));
        m_scanStartButton->setEnabled(true);
    }
    if (m_scanStopButton != nullptr) {
        m_scanStopButton->setEnabled(true);
    }
    if (m_scanAutoIpCheck != nullptr
        && m_scanAutoIpCheck->isChecked()
        && !m_settings->value(QStringLiteral("scan_routed_ranges"), false).toBool(false)) {
        applyRangeFromCurrentAdapter();
    }
    resetScanLog();
    appendScanLogLine(QStringLiteral("start range=%1-%2 adapter=%3 profile=%4 workers=%5 auto_workers=%6")
        .arg(m_scanStartIp != nullptr ? m_scanStartIp->text().trimmed() : QString())
        .arg(m_scanEndIp != nullptr ? m_scanEndIp->text().trimmed() : QString())
        .arg(m_scanAdapterCombo != nullptr ? m_scanAdapterCombo->currentData().toString() : QString())
        .arg(scanProfile)
        .arg(scanWorkers)
        .arg(autoWorkers ? QStringLiteral("true") : QStringLiteral("false")));
    clearScanTable();
    m_scanRows.clear();
    m_scanNewIps.clear();
    m_scanRefreshMisses.clear();
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(uiText(m_settings, "Онлайн: 0", "Online: 0"));
    }
    QPointer<nt::VendorDbService> vendorDb(m_vendorDb);
    (void)QtConcurrent::run([vendorDb]() {
        if (vendorDb != nullptr) {
            vendorDb->ensureReady(false);
        }
    });
    updateScanFooter(localizedScanScanningText(m_settings));
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, 0));
    }
    if (m_scanStartButton != nullptr) {
        m_scanStartButton->repaint();
    }
    if (m_scanFooterStateLabel != nullptr) {
        m_scanFooterStateLabel->repaint();
    }
    qApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers);
    m_scanner->start(
        m_scanStartIp->text().trimmed(),
        m_scanEndIp->text().trimmed(),
        m_scanAdapterCombo->currentData().toString(),
        scanWorkers,
        scanProfile,
        m_currentScanGeneration
    );
}

void MainWindow::stopScan() {
    const bool backgroundRefresh = m_scanBackgroundRefreshRun;
    ++m_currentScanGeneration;
    m_scanLaunchPending = false;
    m_scanBackgroundRefreshRun = false;
    m_scanPolishingActive = false;
    if (m_scanner != nullptr) {
        m_scanner->cancel();
    }
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
    appendScanLogLine(QStringLiteral("%1 devices=%2").arg(backgroundRefresh ? QStringLiteral("background_refresh_stop") : QStringLiteral("stop")).arg(m_scanRows.size()));
    updateScanFooter(backgroundRefresh
        ? uiText(m_settings, "Фоновое обновление остановлено", "Background refresh stopped")
        : (m_scanAutoScanCheck != nullptr && m_scanAutoScanCheck->isChecked()
            ? uiText(m_settings, "Сканирование остановлено. Авто скан активен", "Scan stopped. Auto scan is enabled")
            : uiText(m_settings, "Сканирование остановлено", "Scan stopped")));
    updateScanBackgroundRefreshTimer();
}

void MainWindow::saveSnapshot() {
    if (m_scanRows.isEmpty()) {
        QMessageBox::information(this, uiText(m_settings, "Снимки", "Snapshots"), uiText(m_settings, "Пока нет результатов сканирования для сохранения.", "There are no scan results to save yet."));
        return;
    }
    bool ok = false;
    const QString name = QInputDialog::getText(
        this,
        uiText(m_settings, "Сохранить снимок", "Save snapshot"),
        uiText(m_settings, "Название снимка", "Snapshot name"),
        QLineEdit::Normal,
        QStringLiteral("baseline"),
        &ok
    );
    if (!ok) {
        return;
    }
    QString path;
    QString error;
    if (!m_snapshots->saveSnapshot(name, m_scanRows, m_scanStartIp->text(), m_scanEndIp->text(), m_scanAdapterCombo->currentText(), &path, &error)) {
        QMessageBox::warning(this, uiText(m_settings, "Снимки", "Snapshots"), error);
        return;
    }
    refreshFavoritesMenu();
    updateScanFooter(uiText(m_settings, "Снимок сохранен: %1", "Snapshot saved: %1").arg(path));
}

void MainWindow::deleteSnapshot() {
    const auto snapshots = m_snapshots->listSnapshots();
    if (snapshots.isEmpty()) {
        QMessageBox::information(
            this,
            uiText(m_settings, "Удаление снимка", "Delete snapshot"),
            uiText(m_settings, "Сохраненных снимков пока нет.", "There are no saved snapshots yet.")
        );
        return;
    }

    QStringList options;
    for (const auto& item : snapshots) {
        options.append(uiText(m_settings, "%1 | %2 | хостов: %3", "%1 | %2 | hosts: %3").arg(item.name, item.createdAt.left(19), QString::number(item.rowCount)));
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(
        this,
        uiText(m_settings, "Удаление снимка", "Delete snapshot"),
        uiText(m_settings, "Выберите снимок", "Choose snapshot"),
        options,
        0,
        false,
        &ok
    );
    if (!ok || choice.isEmpty()) {
        return;
    }

    const int index = options.indexOf(choice);
    if (index < 0 || index >= snapshots.size()) {
        return;
    }

    const auto snapshot = snapshots.at(index);
    const auto answer = QMessageBox::question(
        this,
        uiText(m_settings, "Удаление снимка", "Delete snapshot"),
        uiText(m_settings, "Удалить снимок \"%1\"?", "Delete snapshot \"%1\"?").arg(snapshot.name),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );
    if (answer != QMessageBox::Yes) {
        return;
    }

    QString error;
    if (!m_snapshots->deleteSnapshot(snapshot.path, &error)) {
        QMessageBox::warning(this, uiText(m_settings, "Удаление снимка", "Delete snapshot"), error);
        return;
    }

    refreshFavoritesMenu();
    updateScanFooter(uiText(m_settings, "Снимок удален: %1", "Snapshot deleted: %1").arg(snapshot.name));
}

void MainWindow::compareSnapshot() {
    const auto snapshots = m_snapshots->listSnapshots();
    if (snapshots.isEmpty()) {
        QMessageBox::information(this, uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"), uiText(m_settings, "Сохраненных снимков пока нет.", "There are no saved snapshots yet."));
        return;
    }

    QStringList options;
    for (const auto& item : snapshots) {
        options.append(uiText(m_settings, "%1 | %2 | хостов: %3", "%1 | %2 | hosts: %3").arg(item.name, item.createdAt.left(19), QString::number(item.rowCount)));
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(
        this,
        uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"),
        uiText(m_settings, "Сохраненные снимки", "Saved snapshots"),
        options,
        0,
        false,
        &ok
    );
    if (!ok || choice.isEmpty()) {
        return;
    }
    const int index = options.indexOf(choice);
    if (index < 0 || index >= snapshots.size()) {
        return;
    }
    compareSnapshotPath(snapshots.at(index).path);
}

void MainWindow::compareSnapshotPath(const QString& path) {
    nt::SnapshotMeta meta;
    QString error;
    const auto rows = m_snapshots->loadSnapshotRows(path, &meta, &error);
    if (!error.isEmpty()) {
        QMessageBox::warning(this, uiText(m_settings, "Сравнение со снимком", "Compare with snapshot"), error);
        return;
    }

    const auto summary = m_snapshots->diffRows(rows, m_scanRows);
    showSnapshotDiffDialog(meta, summary);
}

void MainWindow::refreshFavoritesMenu() {
    if (m_favoritesMenu == nullptr) {
        return;
    }
    m_favoritesMenu->clear();
    m_favoritesMenu->addAction(uiText(m_settings, "Сохранить текущий снимок", "Save current snapshot"), this, &MainWindow::saveSnapshot);
    m_favoritesMenu->addAction(uiText(m_settings, "Удалить снимок...", "Delete snapshot..."), this, &MainWindow::deleteSnapshot);
    m_favoritesMenu->addAction(uiText(m_settings, "Сравнить со снимком...", "Compare with snapshot..."), this, &MainWindow::compareSnapshot);
    auto* compareAction = m_favoritesMenu->addAction(uiText(m_settings, "Сравнение сканов", "Scan comparison"));
    compareAction->setCheckable(true);
    compareAction->setChecked(m_scanCompareMode);
    connect(compareAction, &QAction::toggled, this, &MainWindow::toggleScanCompareMode);
    const auto snapshots = m_snapshots->listSnapshots();
    m_favoritesMenu->addSeparator();
    if (snapshots.isEmpty()) {
        auto* emptyAction = m_favoritesMenu->addAction(uiText(m_settings, "Пока пусто", "Empty"));
        emptyAction->setEnabled(false);
        return;
    }
    for (const auto& snapshot : snapshots) {
        const QString label = QStringLiteral("%1 | %2 | %3").arg(snapshot.name, snapshot.createdAt.left(19), QString::number(snapshot.rowCount));
        m_favoritesMenu->addAction(label, this, [this, path = snapshot.path]() { compareSnapshotPath(path); });
    }
}

void MainWindow::showSnapshotDiffDialog(const nt::SnapshotMeta& meta, const nt::SnapshotDiffSummary& summary) {
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("Diff | %1").arg(meta.name));
    dialog->resize(980, 560);

    auto* root = new QVBoxLayout(dialog);
    auto* chips = new QHBoxLayout();

    const auto addChip = [chips](const QString& text, const QColor& color) {
        auto* label = new QLabel(text);
        label->setStyleSheet(QStringLiteral("QLabel { color:%1; font-weight:700; padding:2px 4px; }").arg(color.name()));
        chips->addWidget(label);
    };

    addChip(uiText(m_settings, "+ Добавлено: %1", "+ Added: %1").arg(summary.added), QColor("#6fd27f"));
    addChip(uiText(m_settings, "- Вышло: %1", "- Removed: %1").arg(summary.removed), QColor("#ef7b7b"));
    addChip(uiText(m_settings, "~ Изменено: %1", "~ Changed: %1").arg(summary.changed), QColor("#f2c36a"));
    chips->addStretch(1);
    root->addLayout(chips);

    auto* info = new QLabel(uiText(m_settings, "%1 | %2 | Хостов в снимке: %3", "%1 | %2 | Hosts in snapshot: %3").arg(meta.name, meta.createdAt.left(19), QString::number(meta.rowCount)), dialog);
    root->addWidget(info);

    auto* table = new QTableWidget(dialog);
    table->setColumnCount(5);
    table->setHorizontalHeaderLabels({
        uiText(m_settings, "Тип", "Type"),
        QStringLiteral("IP"),
        uiText(m_settings, "Было", "Before"),
        uiText(m_settings, "Стало", "After"),
        uiText(m_settings, "Детали", "Details"),
    });
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    table->setRowCount(summary.entries.size());

    for (int row = 0; row < summary.entries.size(); ++row) {
        const auto& entry = summary.entries.at(row);
        QString kindLabel;
        QColor fg;
        if (entry.kind == nt::SnapshotDiffKind::Added) {
            kindLabel = QStringLiteral("+ Added");
            fg = QColor("#6fd27f");
        } else if (entry.kind == nt::SnapshotDiffKind::Removed) {
            kindLabel = QStringLiteral("- Removed");
            fg = QColor("#ef7b7b");
        } else {
            kindLabel = QStringLiteral("~ Changed");
            fg = QColor("#f2c36a");
        }
        const QStringList columns {kindLabel, entry.ip, entry.beforeValue, entry.afterValue, entry.details};
        for (int col = 0; col < columns.size(); ++col) {
            auto* item = new QTableWidgetItem(columns.at(col));
            if (col == 0) {
                item->setForeground(fg);
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            }
            if (col == 4) {
                item->setToolTip(entry.details);
            }
            table->setItem(row, col, item);
        }
    }

    root->addWidget(table, 1);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    root->addWidget(buttons);
    dialog->show();
}

void MainWindow::clearScanTable() {
    m_scanTable->setRowCount(0);
    for (auto it = m_hostLabels.begin(); it != m_hostLabels.end(); ++it) {
        it.value()->setText(localizedMissingText(m_settings));
    }
}

void MainWindow::rebuildScanTable() {
    if (m_scanTable == nullptr) {
        return;
    }
    m_scanTable->setRowCount(0);
    QList<nt::ScanRecord> sortedRows = m_scanRows;
    std::sort(sortedRows.begin(), sortedRows.end(), [this](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        const quint32 leftIp = ipToInt(left.ip);
        const quint32 rightIp = ipToInt(right.ip);
        return m_scanSortAscending ? leftIp < rightIp : leftIp > rightIp;
    });
    for (const auto& record : sortedRows) {
        const nt::ScanRecord& safeRecord = record;
        if (safeRecord.ip.isEmpty()) {
            continue;
        }
        int rowIndex = findRowByIp(m_scanTable, safeRecord.ip);
        if (rowIndex < 0) {
            rowIndex = insertionRowForIp(m_scanTable, safeRecord.ip, m_scanSortAscending);
            m_scanTable->insertRow(rowIndex);
        }

        const QList<QString> values = {
            safeRecord.ip,
            displayCellValue(m_settings, safeRecord.pingDisplay, QStringLiteral("[n/a]")),
            displayCellValue(m_settings, safeRecord.mac, QStringLiteral("-")),
            displayCellValue(m_settings, safeRecord.vendor, QStringLiteral("unknown vendor")),
            normalizedHostNameText(m_settings, safeRecord.hostName),
            normalizedWebDetectText(m_settings, safeRecord.webDetect),
            displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-")),
            scanPortCellText(m_settings, safeRecord.port),
            normalizedTypeText(m_settings, safeRecord.typeHint),
        };
        const QString gatewayValue = displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-"));
        const bool isGatewayHost = gatewayValue != localizedMissingText(m_settings) && safeRecord.ip == gatewayValue;
        const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
        const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
        const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
        const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");
        const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(safeRecord.ip);

        for (int col = 0; col < values.size(); ++col) {
            auto* item = m_scanTable->item(rowIndex, col);
            if (item == nullptr) {
                item = new QTableWidgetItem();
                m_scanTable->setItem(rowIndex, col, item);
            }
            item->setText(col == ScanColumnIp ? scanIpCellText(safeRecord.ip, isNewHost) : values.at(col));
            item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
            if (col == ScanColumnIp) {
                item->setData(Qt::UserRole, safeRecord.ip);
            }
            if (col == ScanColumnType) {
                item->setData(Qt::UserRole, normalizedTypeText(m_settings, safeRecord.typeHint));
                item->setText(scanTypeCellText(m_settings, safeRecord.typeHint, isNewHost));
                item->setTextAlignment(Qt::AlignCenter);
                item->setToolTip(item->text());
            }
            if (col == ScanColumnHostName || col == ScanColumnWeb || col == ScanColumnPort) {
                item->setToolTip(item->text());
            }
            if (col == ScanColumnPort || col == ScanColumnWeb || col == ScanColumnType) {
                item->setTextAlignment(Qt::AlignCenter);
            }
            if (col == ScanColumnIp && isNewHost) {
                item->setForeground(QBrush(QColor("#7fda72")));
            } else {
                item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
            }
            QFont font = item->font();
            font.setBold(isGatewayHost || (col == ScanColumnIp && isNewHost));
            item->setFont(font);
            if (col == ScanColumnIp) {
                item->setIcon(statusOrb(safeRecord.status));
                item->setToolTip(
                    uiText(m_settings, "Статус: %1\nMAC: %2\nВендор: %3\nHostname: %4\nWeb: %5\nШлюз IP: %6\nОткрытые порты: %7\nТип: %8\nМаршрут: %9\nМаска: %10%11",
                           "Status: %1\nMAC: %2\nVendor: %3\nHostname: %4\nWeb: %5\nGateway IP: %6\nOpen ports: %7\nType: %8\nRoute: %9\nMask: %10%11")
                        .arg(localizedHostStatusText(m_settings, safeRecord.status))
                        .arg(displayCellValue(m_settings, safeRecord.mac, QStringLiteral("-")))
                        .arg(displayCellValue(m_settings, safeRecord.vendor, QStringLiteral("unknown vendor")))
                        .arg(normalizedHostNameText(m_settings, safeRecord.hostName))
                        .arg(normalizedWebDetectText(m_settings, safeRecord.webDetect))
                        .arg(displayCellValue(m_settings, safeRecord.gateway, QStringLiteral("-")))
                        .arg(scanPortCellText(m_settings, safeRecord.port))
                        .arg(normalizedTypeText(m_settings, safeRecord.typeHint))
                        .arg(displayCellValue(m_settings, safeRecord.name, QStringLiteral("-")))
                        .arg(displayCellValue(m_settings, safeRecord.mask, QStringLiteral("-")))
                        .arg(isGatewayHost ? uiText(m_settings, "\nУзел является шлюзом сети.", "\nThis host is the network gateway.") : QString())
                );
            }
        }
    }
    applyScanColumnVisibility();
    refreshScanComparisonBadges();
    applyScanTableFilter();
}

void MainWindow::applyScanTableFilter() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QString needle = m_scanFilterEdit == nullptr ? QString() : m_scanFilterEdit->text().trimmed().toLower();
    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        auto* ipItem = m_scanTable->item(row, ScanColumnIp);
        if (ipItem == nullptr) {
            continue;
        }
        const QString ip = scanIpFromItem(ipItem);
        const auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
            return record.ip == ip;
        });
        const bool visible = it != m_scanRows.end() ? scanRecordMatchesFilter(*it, needle) : needle.isEmpty();
        m_scanTable->setRowHidden(row, !visible);
    }
}

void MainWindow::applyScanColumnVisibility() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QJsonObject saved = m_settings->section(QStringLiteral("scan_columns"));
    for (int column = 0; column < ScanColumnCount; ++column) {
        auto* action = m_scanColumnActions.value(column, nullptr);
        bool visible = scanColumnVisibleByDefault(column);
        if (saved.contains(scanColumnKey(column))) {
            visible = saved.value(scanColumnKey(column)).toBool(visible);
        } else if (action != nullptr) {
            visible = action->isChecked();
        }
        if (column == ScanColumnIp) {
            visible = true;
        }
        if (action != nullptr && action->isChecked() != visible) {
            QSignalBlocker blocker(action);
            action->setChecked(visible);
        }
        m_scanTable->setColumnHidden(column, !visible);
    }
}

void MainWindow::saveScanColumnVisibility() const {
    QJsonObject section;
    for (int column = 0; column < ScanColumnCount; ++column) {
        const auto* action = m_scanColumnActions.value(column, nullptr);
        section.insert(scanColumnKey(column), column == ScanColumnIp ? true : (action != nullptr && action->isChecked()));
    }
    m_settings->setSection(QStringLiteral("scan_columns"), section);
    m_settings->save();
}

void MainWindow::applyScanColumnWidths() {
    if (m_scanTable == nullptr) {
        return;
    }
    auto* header = m_scanTable->horizontalHeader();
    QSignalBlocker blocker(header);
    const QJsonObject saved = m_settings->section(QStringLiteral("scan_column_widths"));
    for (int column = 0; column < ScanColumnCount; ++column) {
        header->setSectionResizeMode(column, QHeaderView::Interactive);
        const int width = qBound(44, saved.value(scanColumnKey(column)).toInt(defaultScanColumnWidth(column)), 1200);
        m_scanTable->setColumnWidth(column, width);
    }
}

void MainWindow::saveScanColumnWidths() const {
    if (m_scanTable == nullptr) {
        return;
    }
    QJsonObject section;
    for (int column = 0; column < ScanColumnCount; ++column) {
        section.insert(scanColumnKey(column), qBound(44, m_scanTable->columnWidth(column), 1200));
    }
    m_settings->setSection(QStringLiteral("scan_column_widths"), section);
    m_settings->save();
}

void MainWindow::resetScanLog() {
    m_scanLogPath = ipScanLogPath();
    QFile file(m_scanLogPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }
    QTextStream out(&file);
    out << "Network Tools IP scan log\n";
    out << "started_at=" << QDateTime::currentDateTime().toString(Qt::ISODateWithMs) << '\n';
}

void MainWindow::appendScanLogLine(const QString& line) {
    if (m_scanLogPath.isEmpty()) {
        m_scanLogPath = ipScanLogPath();
    }
    QFile file(m_scanLogPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        return;
    }
    QTextStream out(&file);
    out << '[' << QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")) << "] " << line << '\n';
}

void MainWindow::openScanLog() {
    if (m_scanLogPath.isEmpty()) {
        m_scanLogPath = ipScanLogPath();
    }
    openIpScanLogFile();
}

void MainWindow::updateScanSortButton() {
    if (m_scanSortButton == nullptr) {
        return;
    }
    m_scanSortButton->setText(m_scanSortAscending ? QStringLiteral("\u2191") : QStringLiteral("\u2193"));
    m_scanSortButton->setToolTip(
        m_scanSortAscending
            ? uiText(m_settings, "Сортировка по IP: по возрастанию", "IP sort: ascending")
            : uiText(m_settings, "Сортировка по IP: по убыванию", "IP sort: descending")
    );
}

void MainWindow::toggleScanSortOrder() {
    m_scanSortAscending = !m_scanSortAscending;
    updateScanSortButton();
    rebuildScanTable();
}

void MainWindow::refreshScanToolbarIcons() {
    const QColor iconColor = isLightTheme() ? QColor("#5f6a76") : QColor("#c1ccd8");
    if (m_scanToolsButton != nullptr) {
        m_scanToolsButton->setIcon(scanGearIcon(iconColor));
        m_scanToolsButton->setIconSize(QSize(18, 18));
    }
    updateScanProfileButton();
}

void MainWindow::updateScanProfileButton() {
    if (m_scanProfileButton == nullptr) {
        return;
    }
    const QString profile = normalizedScanProfileForUi(m_settings != nullptr ? m_settings->scanProfile() : QStringLiteral("fast"));
    const QColor iconColor = isLightTheme() ? QColor("#5f6a76") : QColor("#c1ccd8");
    m_scanProfileButton->setIcon(scanGaugeIcon(iconColor, profile));
    m_scanProfileButton->setIconSize(QSize(19, 19));
    m_scanProfileButton->setToolTip(scanProfileDescription(m_settings, profile));
    for (auto it = m_scanProfileActions.begin(); it != m_scanProfileActions.end(); ++it) {
        if (it.value() != nullptr) {
            QSignalBlocker blocker(it.value());
            it.value()->setChecked(it.key() == profile);
        }
    }
}

void MainWindow::setScanProfile(const QString& profile) {
    if (m_settings == nullptr) {
        return;
    }
    const QString normalized = normalizedScanProfileForUi(profile);
    m_settings->setValue(QStringLiteral("scan_profile"), normalized);
    m_settings->setValue(QStringLiteral("scan_profile_user_selected"), true);
    m_settings->save();
    updateScanProfileButton();
    updateScanFooter(uiText(m_settings, "Режим скана: %1", "Scan mode: %1").arg(scanProfileTitle(m_settings, normalized)));
}

int MainWindow::findRowByIp(QTableWidget* table, const QString& ip) {
    for (int row = 0; row < table->rowCount(); ++row) {
        const auto* item = table->item(row, 0);
        if (item != nullptr && scanIpFromItem(item) == ip) {
            return row;
        }
    }
    return -1;
}

void MainWindow::appendScanRecord(const nt::ScanRecord& record) {
    if (record.ip.isEmpty() || record.generation != m_currentScanGeneration) {
        return;
    }

    nt::ScanRecord displayRecord = record;
    bool updated = false;
    for (auto& existing : m_scanRows) {
        if (existing.ip == record.ip) {
            mergeScanDisplayFields(displayRecord, existing);
            existing = displayRecord;
            updated = true;
            break;
        }
    }
    if (!updated) {
        m_scanRows.append(displayRecord);
    }
    if (m_scanCompareMode && m_scanCompareHasBaseline && !m_scanComparisonBaseline.contains(displayRecord.ip)) {
        m_scanNewIps.insert(displayRecord.ip);
    }
    appendScanLogLine(QStringLiteral("%1 ip=%2 status=%3 ping=%4 mac=%5 vendor=%6 hostname=%7 web=%8 gateway=%9 ports=%10 type=%11")
        .arg(updated ? QStringLiteral("update") : QStringLiteral("found"))
        .arg(displayRecord.ip)
        .arg(localizedHostStatusText(m_settings, displayRecord.status))
        .arg(displayCellValue(m_settings, displayRecord.pingDisplay, QStringLiteral("[n/a]")))
        .arg(displayCellValue(m_settings, displayRecord.mac, QStringLiteral("-")))
        .arg(displayCellValue(m_settings, displayRecord.vendor, QStringLiteral("unknown vendor")))
        .arg(normalizedHostNameText(m_settings, displayRecord.hostName))
        .arg(normalizedWebDetectText(m_settings, displayRecord.webDetect))
        .arg(displayCellValue(m_settings, displayRecord.gateway, QStringLiteral("-")))
        .arg(scanPortCellText(m_settings, displayRecord.port))
        .arg(normalizedTypeText(m_settings, displayRecord.typeHint)));

    int rowIndex = findRowByIp(m_scanTable, displayRecord.ip);
    if (rowIndex < 0) {
        rowIndex = insertionRowForIp(m_scanTable, displayRecord.ip, m_scanSortAscending);
        m_scanTable->insertRow(rowIndex);
    }

    const QList<QString> values = {
        displayRecord.ip,
        displayCellValue(m_settings, displayRecord.pingDisplay, QStringLiteral("[n/a]")),
        displayCellValue(m_settings, displayRecord.mac, QStringLiteral("-")),
        displayCellValue(m_settings, displayRecord.vendor, QStringLiteral("unknown vendor")),
        normalizedHostNameText(m_settings, displayRecord.hostName),
        normalizedWebDetectText(m_settings, displayRecord.webDetect),
        displayCellValue(m_settings, displayRecord.gateway, QStringLiteral("-")),
        scanPortCellText(m_settings, displayRecord.port),
        normalizedTypeText(m_settings, displayRecord.typeHint),
    };
    const QString gatewayValue = displayCellValue(m_settings, displayRecord.gateway, QStringLiteral("-"));
    const bool isGatewayHost = gatewayValue != localizedMissingText(m_settings) && displayRecord.ip == gatewayValue;
    const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");
    const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(displayRecord.ip);

    for (int col = 0; col < values.size(); ++col) {
        auto* item = m_scanTable->item(rowIndex, col);
        if (item == nullptr) {
            item = new QTableWidgetItem();
            m_scanTable->setItem(rowIndex, col, item);
        }
        const QString cellText = col == ScanColumnIp ? scanIpCellText(displayRecord.ip, isNewHost) : values.at(col);
        if (item->text() != cellText) {
            item->setText(cellText);
        }
        item->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
        if (col == ScanColumnIp) {
            item->setData(Qt::UserRole, displayRecord.ip);
        }
        if (col == ScanColumnType) {
            item->setData(Qt::UserRole, normalizedTypeText(m_settings, displayRecord.typeHint));
            item->setText(scanTypeCellText(m_settings, displayRecord.typeHint, isNewHost));
            item->setTextAlignment(Qt::AlignCenter);
            item->setToolTip(item->text());
        }
        if (col == ScanColumnHostName || col == ScanColumnWeb || col == ScanColumnPort) {
            item->setToolTip(item->text());
        }
        if (col == ScanColumnPort || col == ScanColumnWeb || col == ScanColumnType) {
            item->setTextAlignment(Qt::AlignCenter);
        }
        if (col == ScanColumnIp && isNewHost) {
            item->setForeground(QBrush(QColor("#7fda72")));
        } else {
            item->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
        }
        QFont font = item->font();
        font.setBold(isGatewayHost || (col == ScanColumnIp && isNewHost));
        item->setFont(font);
        if (col == ScanColumnIp) {
            item->setIcon(statusOrb(displayRecord.status));
            item->setToolTip(
                uiText(m_settings, "Статус: %1\nMAC: %2\nВендор: %3\nHostname: %4\nWeb: %5\nШлюз IP: %6\nОткрытые порты: %7\nТип: %8\nМаршрут: %9\nМаска: %10%11",
                       "Status: %1\nMAC: %2\nVendor: %3\nHostname: %4\nWeb: %5\nGateway IP: %6\nOpen ports: %7\nType: %8\nRoute: %9\nMask: %10%11")
                    .arg(localizedHostStatusText(m_settings, displayRecord.status))
                    .arg(displayCellValue(m_settings, displayRecord.mac, QStringLiteral("-")))
                    .arg(displayCellValue(m_settings, displayRecord.vendor, QStringLiteral("unknown vendor")))
                    .arg(normalizedHostNameText(m_settings, displayRecord.hostName))
                    .arg(normalizedWebDetectText(m_settings, displayRecord.webDetect))
                    .arg(displayCellValue(m_settings, displayRecord.gateway, QStringLiteral("-")))
                    .arg(scanPortCellText(m_settings, displayRecord.port))
                    .arg(normalizedTypeText(m_settings, displayRecord.typeHint))
                    .arg(displayCellValue(m_settings, displayRecord.name, QStringLiteral("-")))
                    .arg(displayCellValue(m_settings, displayRecord.mask, QStringLiteral("-")))
                    .arg(isGatewayHost ? uiText(m_settings, "\nУзел является шлюзом сети.", "\nThis host is the network gateway.") : QString())
            );
        }
    }

    updateScanSummary();
    refreshScanComparisonBadges();
    applyScanTableFilter();
}

void MainWindow::finalizeScanBackgroundRefresh(const QList<nt::ScanRecord>& records, int durationMs) {
    m_scanLaunchPending = false;
    const QList<nt::ScanRecord> previousRows = m_scanRows;
    QSet<QString> refreshedIps;
    QList<nt::ScanRecord> sortedRecords = records;
    std::sort(sortedRecords.begin(), sortedRecords.end(), [this](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        const quint32 leftIp = ipToInt(left.ip);
        const quint32 rightIp = ipToInt(right.ip);
        return m_scanSortAscending ? leftIp < rightIp : leftIp > rightIp;
    });

    int added = 0;
    int updated = 0;
    int removed = 0;
    for (auto record : sortedRecords) {
        if (record.ip.trimmed().isEmpty()) {
            continue;
        }
        refreshedIps.insert(record.ip);
        const auto previousIt = std::find_if(previousRows.constBegin(), previousRows.constEnd(), [&](const nt::ScanRecord& previous) {
            return previous.ip == record.ip;
        });
        const bool existed = previousIt != previousRows.constEnd();
        if (existed) {
            mergeScanDisplayFields(record, *previousIt);
            ++updated;
        } else {
            ++added;
        }
        m_scanRefreshMisses.remove(record.ip);
        appendScanRecord(record);
    }

    for (const auto& previous : previousRows) {
        if (previous.ip.trimmed().isEmpty() || refreshedIps.contains(previous.ip)) {
            continue;
        }
        const int missCount = m_scanRefreshMisses.value(previous.ip, 0) + 1;
        m_scanRefreshMisses.insert(previous.ip, missCount);
        if (missCount < 2) {
            continue;
        }

        m_scanRefreshMisses.remove(previous.ip);
        auto rowIt = std::remove_if(m_scanRows.begin(), m_scanRows.end(), [&](const nt::ScanRecord& row) {
            return row.ip == previous.ip;
        });
        if (rowIt != m_scanRows.end()) {
            m_scanRows.erase(rowIt, m_scanRows.end());
        }
        const int tableRow = findRowByIp(m_scanTable, previous.ip);
        if (tableRow >= 0) {
            m_scanTable->removeRow(tableRow);
        }
        m_scanNewIps.remove(previous.ip);
        m_scanComparisonBaseline.remove(previous.ip);
        ++removed;
        appendScanLogLine(QStringLiteral("background_refresh_removed ip=%1 misses=%2").arg(previous.ip).arg(missCount));
    }

    m_scanBackgroundRefreshRun = false;
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
    updateScanSummary();
    updateSelectedHostPanel();
    refreshScanComparisonBadges();
    applyScanTableFilter();
    updateScanFooter(localizedScanRefreshFinishedText(m_settings, updated, added, removed, durationMs));
    appendScanLogLine(QStringLiteral("background_refresh_finished updated=%1 added=%2 removed=%3 duration_ms=%4")
        .arg(updated)
        .arg(added)
        .arg(removed)
        .arg(durationMs));
    updateScanBackgroundRefreshTimer();
}

void MainWindow::finalizeScan(const QList<nt::ScanRecord>& records, int durationMs) {
    if (!records.isEmpty() && records.first().generation != m_currentScanGeneration) {
        return;
    }
    m_scanLaunchPending = false;
    if (m_scanBackgroundRefreshRun) {
        finalizeScanBackgroundRefresh(records, durationMs);
        return;
    }
    m_scanPolishingActive = true;
    const quint64 finishedGeneration = m_currentScanGeneration;
    const QList<nt::ScanRecord> previousRows = m_scanRows;
    QList<nt::ScanRecord> sortedRecords = records;
    for (auto& record : sortedRecords) {
        const auto previousIt = std::find_if(previousRows.constBegin(), previousRows.constEnd(), [&](const nt::ScanRecord& previous) {
            return previous.ip == record.ip;
        });
        if (previousIt != previousRows.constEnd()) {
            mergeScanDisplayFields(record, *previousIt);
        }
    }
    std::sort(sortedRecords.begin(), sortedRecords.end(), [this](const nt::ScanRecord& left, const nt::ScanRecord& right) {
        const quint32 leftIp = ipToInt(left.ip);
        const quint32 rightIp = ipToInt(right.ip);
        return m_scanSortAscending ? leftIp < rightIp : leftIp > rightIp;
    });
    m_scanRows = sortedRecords;
    rebuildScanTable();
    if (m_scanTable != nullptr) {
        m_scanTable->viewport()->update();
    }
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
    if (m_scanCompareMode) {
        QSet<QString> currentIps;
        for (const auto& record : m_scanRows) {
            currentIps.insert(record.ip);
        }
        if (!m_scanCompareHasBaseline) {
            m_scanNewIps.clear();
            m_scanCompareHasBaseline = true;
        } else {
            m_scanNewIps = currentIps - m_scanComparisonBaseline;
        }
        m_scanComparisonBaseline = currentIps;
        refreshScanComparisonBadges();
    } else {
        m_scanComparisonBaseline.clear();
        m_scanNewIps.clear();
        m_scanCompareHasBaseline = false;
        refreshScanComparisonBadges();
    }
    updateScanSummary();
    updateSelectedHostPanel();
    m_scanRefreshMisses.clear();
    updateScanFooter(localizedScanPolishingText(m_settings));
    appendScanLogLine(QStringLiteral("main_scan_finished devices=%1 duration_ms=%2 polishing=true").arg(m_scanRows.size()).arg(durationMs));
    QTimer::singleShot(2800, this, [this, finishedGeneration, durationMs]() {
        if (finishedGeneration != m_currentScanGeneration
            || m_scanner == nullptr
            || m_scanner->isRunning()
            || !m_scanPolishingActive) {
            return;
        }
        m_scanPolishingActive = false;
        appendScanLogLine(QStringLiteral("finished duration_ms=%1").arg(durationMs));
        updateScanFooter(localizedScanFinishedText(m_settings, durationMs));
        updateScanBackgroundRefreshTimer();
    });
    updateScanBackgroundRefreshTimer();
}

void MainWindow::updateScanSummary() {
    int online = 0;
    int offline = 0;
    int detected = 0;
    int macCount = 0;
    for (const auto& row : m_scanRows) {
        if (row.status == nt::HostStatus::Online) {
            ++online;
            ++detected;
        } else if (row.status == nt::HostStatus::Unknown) {
            ++detected;
        } else if (row.status == nt::HostStatus::Offline) {
            ++offline;
        }
        if (!row.mac.trimmed().isEmpty() && row.mac != QStringLiteral("-")) {
            ++macCount;
        }
    }
    if (m_scanOnlineLabel != nullptr) {
        m_scanOnlineLabel->setText(
            isEnglishUi(m_settings)
                ? QStringLiteral("Online: %1").arg(online)
                : QStringLiteral("Онлайн: %1").arg(online)
        );
    }
    if (m_scanFooterThreadsLabel != nullptr) {
        m_scanFooterThreadsLabel->setText(localizedFoundDevicesText(m_settings, m_scanRows.size()));
    }
    if (m_scanFooterStateLabel != nullptr && !m_scanner->isRunning() && !m_scanPolishingActive) {
        updateScanFooter(localizedScanSummaryText(m_settings, m_scanRows.size(), online, macCount));
    }
}

void MainWindow::updateScanFooter(const QString& stateText) {
    if (m_scanFooterStateLabel != nullptr && !stateText.isEmpty()) {
        m_scanFooterStateLabel->setText(stateText);
        const bool comparisonAccent = stateText == localizedComparisonModeText(m_settings);
        const bool scanningAccent = stateText == localizedScanScanningText(m_settings);
        const bool polishingAccent = stateText == localizedScanPolishingText(m_settings);
        const bool refreshingAccent = stateText == localizedScanRefreshingText(m_settings);
        if (comparisonAccent || scanningAccent) {
            m_scanFooterStateLabel->setStyleSheet(QStringLiteral(
                "QLabel#statusCell { color:#f2c36a; font-weight:700; background:transparent; border:none; padding:3px 7px; font-size:11px; }"
            ));
        } else if (polishingAccent) {
            m_scanFooterStateLabel->setStyleSheet(QStringLiteral(
                "QLabel#statusCell { color:#7fda72; font-weight:700; background:transparent; border:none; padding:3px 7px; font-size:11px; }"
            ));
        } else if (refreshingAccent) {
            m_scanFooterStateLabel->setStyleSheet(QStringLiteral(
                "QLabel#statusCell { color:#66a8ff; font-weight:700; background:transparent; border:none; padding:3px 7px; font-size:11px; }"
            ));
        } else {
            m_scanFooterStateLabel->setStyleSheet(QString());
        }
    }
}

void MainWindow::updateSelectedHostPanel() {
    if (m_hostLabels.isEmpty()) {
        return;
    }
    const int row = m_scanTable->currentRow();
    if (row < 0) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr) {
        return;
    }
    const QString selectedIp = scanIpFromItem(ipItem);
    auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
        return record.ip == selectedIp;
    });
    if (it == m_scanRows.end()) {
        return;
    }
    const auto& item = *it;
    m_hostLabels.value(QStringLiteral("ip"))->setText(item.ip);
    m_hostLabels.value(QStringLiteral("status"))->setText(localizedHostStatusIndicator(m_settings, item.status));
    m_hostLabels.value(QStringLiteral("mac"))->setText(displayCellValue(m_settings, item.mac, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("vendor"))->setText(displayCellValue(m_settings, item.vendor, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("type"))->setText(normalizedTypeText(m_settings, item.typeHint));
    m_hostLabels.value(QStringLiteral("name"))->setText(displayCellValue(m_settings, item.name, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("gateway"))->setText(displayCellValue(m_settings, item.gateway, QStringLiteral("-")));
    m_hostLabels.value(QStringLiteral("mask"))->setText(displayCellValue(m_settings, item.mask, QStringLiteral("-")));
}

void MainWindow::toggleScanCompareMode(bool enabled) {
    m_scanCompareMode = enabled;
    m_scanComparisonBaseline.clear();
    m_scanNewIps.clear();
    m_scanCompareHasBaseline = false;
    refreshFavoritesMenu();
    refreshScanComparisonBadges();
    if (enabled) {
        updateScanFooter(localizedComparisonModeText(m_settings));
        return;
    }
    if (m_scanner != nullptr && m_scanner->isRunning()) {
        updateScanFooter(localizedScanScanningText(m_settings));
    } else {
        updateScanSummary();
    }
}

void MainWindow::refreshScanComparisonBadges() {
    if (m_scanTable == nullptr) {
        return;
    }
    const QColor defaultBackground = isLightTheme() ? QColor("#f5f7f8") : QColor("#0f1318");
    const QColor defaultForeground = isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6");
    const QColor gatewayBackground = isLightTheme() ? QColor("#efe2b6") : QColor("#3a301d");
    const QColor gatewayForeground = isLightTheme() ? QColor("#4c3812") : QColor("#f2d38a");

    for (int row = 0; row < m_scanTable->rowCount(); ++row) {
        auto* ipItem = m_scanTable->item(row, ScanColumnIp);
        const auto* gatewayItem = m_scanTable->item(row, ScanColumnGateway);
        auto* badgeItem = m_scanTable->item(row, ScanColumnType);
        if (ipItem == nullptr || badgeItem == nullptr) {
            continue;
        }
        const QString ip = scanIpFromItem(ipItem);
        const bool isGatewayHost = gatewayItem != nullptr
            && !gatewayItem->text().trimmed().isEmpty()
            && gatewayItem->text() != localizedMissingText(m_settings)
            && gatewayItem->text() == ip;
        const bool isNewHost = m_scanCompareMode && m_scanNewIps.contains(ip);
        ipItem->setText(scanIpCellText(ip, isNewHost));
        ipItem->setData(Qt::UserRole, ip);
        ipItem->setForeground(QBrush(isNewHost ? QColor("#7fda72") : (isGatewayHost ? gatewayForeground : defaultForeground)));
        QFont ipFont = ipItem->font();
        ipFont.setBold(isGatewayHost || isNewHost);
        ipItem->setFont(ipFont);
        badgeItem->setText(scanTypeCellText(m_settings, badgeItem->data(Qt::UserRole).toString(), isNewHost));
        badgeItem->setTextAlignment(Qt::AlignCenter);
        badgeItem->setBackground(QBrush(isGatewayHost ? gatewayBackground : defaultBackground));
        badgeItem->setForeground(QBrush(isGatewayHost ? gatewayForeground : defaultForeground));
        badgeItem->setToolTip(badgeItem->text());
        QFont font = badgeItem->font();
        font.setBold(isGatewayHost);
        badgeItem->setFont(font);
    }
    m_scanTable->viewport()->update();
}

void MainWindow::showScanCellDetails(int row, int column) {
    if (m_scanTable == nullptr
        || row < 0
        || row >= m_scanTable->rowCount()
        || (column != ScanColumnPort && column != ScanColumnWeb && column != ScanColumnHostName)) {
        return;
    }

    auto* item = m_scanTable->item(row, column);
    if (item == nullptr) {
        return;
    }

    const QString value = scanPopupValue(item->text(), column);
    if (value.isEmpty()) {
        return;
    }

    const QString title = scanPopupTitle(m_settings, column);
    const QString html = QStringLiteral("<qt><div style='font-weight:700; margin-bottom:4px;'>%1</div><pre style='margin:0; font-family:Menlo, Monaco, monospace;'>%2</pre></qt>")
        .arg(title.toHtmlEscaped(), value.toHtmlEscaped());
    const QRect cellRect = m_scanTable->visualItemRect(item);
    const QPoint anchor = m_scanTable->viewport()->mapToGlobal(QPoint(cellRect.left() + cellRect.width() / 2, qMax(0, cellRect.top() - 8)));
    QToolTip::showText(anchor, html, m_scanTable->viewport(), cellRect, 9000);
}

void MainWindow::openScanContextMenu(const QPoint& position) {
    if (m_scanTable == nullptr) {
        return;
    }
    const QModelIndex index = m_scanTable->indexAt(position);
    if (!index.isValid()) {
        return;
    }
    m_scanTable->selectRow(index.row());

    QMenu menu(this);
    auto* browserAction = menu.addAction(uiText(m_settings, "Открыть в браузере", "Open in browser"));
    auto* pingAction = menu.addAction(uiText(m_settings, "Ping", "Ping"));
    menu.addSeparator();
    auto* sshAction = menu.addAction(uiText(m_settings, "Connect SSH", "Connect SSH"));
    auto* telnetAction = menu.addAction(uiText(m_settings, "Connect Telnet", "Connect Telnet"));

    QAction* selected = menu.exec(m_scanTable->viewport()->mapToGlobal(position));
    if (selected == browserAction) {
        openScanRowInBrowser(index.row());
    } else if (selected == pingAction) {
        openScanRowPing(index.row());
    } else if (selected == sshAction) {
        openScanRowSession(QStringLiteral("ssh"), index.row());
    } else if (selected == telnetAction) {
        openScanRowSession(QStringLiteral("telnet"), index.row());
    }
}

void MainWindow::openScanRowInBrowser(int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || scanIpFromItem(ipItem).trimmed().isEmpty()) {
        return;
    }
    const QString ip = scanIpFromItem(ipItem).trimmed();
    QString targetUrl;
    const auto it = std::find_if(m_scanRows.begin(), m_scanRows.end(), [&](const auto& record) {
        return record.ip == ip;
    });
    if (it != m_scanRows.end()) {
        targetUrl = firstServiceUrl(it->webDetect);
    }
    if (targetUrl.isEmpty()) {
        targetUrl = QStringLiteral("http://%1").arg(ip);
    }
    QDesktopServices::openUrl(QUrl::fromUserInput(targetUrl));
}

void MainWindow::openScanRowPing(int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || scanIpFromItem(ipItem).trimmed().isEmpty()) {
        return;
    }
    if (!openPingInTerminal(scanIpFromItem(ipItem).trimmed())) {
        QMessageBox::warning(this, uiText(m_settings, "Ping", "Ping"), uiText(m_settings, "Не удалось открыть терминал для ping.", "Failed to open terminal for ping."));
    }
}

void MainWindow::openScanRowSession(const QString& kind, int row) {
    if (m_scanTable == nullptr || row < 0 || row >= m_scanTable->rowCount()) {
        return;
    }
    const auto* ipItem = m_scanTable->item(row, 0);
    if (ipItem == nullptr || scanIpFromItem(ipItem).trimmed().isEmpty()) {
        return;
    }
    const QString ip = scanIpFromItem(ipItem).trimmed();
    if (kind == QStringLiteral("ssh")) {
        prepareSessionFromScan(m_sshWidgets, ip, 22, QStringLiteral("SSH"), 5);
    } else {
        prepareSessionFromScan(m_telnetWidgets, ip, 23, QStringLiteral("Telnet"), 6);
    }
}

void MainWindow::prepareSessionFromScan(SessionWidgets& widgets, const QString& host, quint16 port, const QString& kindLabel, int pageIndex) {
    if (host.trimmed().isEmpty()) {
        return;
    }
    if (pageIndex == 5 && m_sshSession->isConnected()) {
        m_sshSession->close();
    } else if (pageIndex == 6 && m_telnetSession->isConnected()) {
        m_telnetSession->close();
    }
    if (m_navList != nullptr) {
        m_navList->setCurrentRow(pageIndex);
    } else {
        syncCurrentPage(pageIndex);
    }
    widgets.nameEdit->setText(QStringLiteral("%1 %2").arg(kindLabel, host));
    widgets.hostEdit->setText(host);
    widgets.portSpin->setValue(port);
    widgets.userEdit->clear();
    widgets.passEdit->clear();
    if (widgets.outputBox != nullptr) {
        widgets.outputBox->clear();
    }
    if (widgets.statusLabel != nullptr) {
        widgets.statusLabel->setText(uiText(m_settings, "Не подключено", "Not connected"));
    }
    if (widgets.connectButton != nullptr) {
        widgets.connectButton->setText(localizedConnectText(m_settings, false));
    }
    if (widgets.userEdit != nullptr) {
        widgets.userEdit->setFocus();
        widgets.userEdit->selectAll();
    }
}
