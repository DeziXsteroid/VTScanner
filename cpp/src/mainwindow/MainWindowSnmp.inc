nt::SessionProfile MainWindow::currentSnmpProfile() const {
    nt::SessionProfile profile;
    profile.host = m_snmpWidgets.hostEdit != nullptr ? m_snmpWidgets.hostEdit->text().trimmed() : QString();
    profile.port = m_snmpWidgets.portSpin != nullptr ? static_cast<quint16>(m_snmpWidgets.portSpin->value()) : 161;
    profile.protocolVersion = m_snmpWidgets.versionCombo != nullptr ? comboValue(m_snmpWidgets.versionCombo) : QStringLiteral("2c");
    profile.snmpReadCommunity = m_snmpWidgets.communityEdit != nullptr ? m_snmpWidgets.communityEdit->text().trimmed() : QString();
    profile.snmpWriteCommunity = m_snmpWidgets.writeCommunityEdit != nullptr ? m_snmpWidgets.writeCommunityEdit->text() : QString();
    profile.snmpV3User = m_snmpWidgets.v3UserEdit != nullptr ? m_snmpWidgets.v3UserEdit->text().trimmed() : QString();
    profile.snmpV3SecurityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr ? comboValue(m_snmpWidgets.v3SecurityLevelCombo) : QStringLiteral("noAuthNoPriv");
    profile.snmpV3AuthProtocol = m_snmpWidgets.v3AuthProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3AuthProtocolCombo) : QStringLiteral("SHA");
    profile.snmpV3AuthPassword = m_snmpWidgets.v3AuthPasswordEdit != nullptr ? m_snmpWidgets.v3AuthPasswordEdit->text() : QString();
    profile.snmpV3PrivacyProtocol = m_snmpWidgets.v3PrivacyProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3PrivacyProtocolCombo) : QStringLiteral("AES");
    profile.snmpV3PrivacyPassword = m_snmpWidgets.v3PrivacyPasswordEdit != nullptr ? m_snmpWidgets.v3PrivacyPasswordEdit->text() : QString();
    if (snmpUsesCommunity(profile.protocolVersion)) {
        profile.username = profile.snmpReadCommunity;
        profile.password = profile.snmpWriteCommunity;
    } else {
        profile.username = profile.snmpV3User;
        profile.password = profile.snmpV3AuthPassword;
    }
    if (profile.port == 0) {
        profile.port = 161;
    }
    profile.name = QStringLiteral("%1:%2").arg(profile.host, QString::number(profile.port));
    return profile;
}

void MainWindow::refreshSnmpVersionUi() {
    if (m_snmpWidgets.versionCombo == nullptr || m_snmpWidgets.securityStack == nullptr) {
        return;
    }
    const QString version = comboValue(m_snmpWidgets.versionCombo);
    const bool communityMode = snmpUsesCommunity(version);
    m_snmpWidgets.securityStack->setCurrentIndex(communityMode ? 0 : 1);

    const QString securityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr
        ? comboValue(m_snmpWidgets.v3SecurityLevelCombo)
        : QStringLiteral("noAuthNoPriv");
    const bool authEnabled = !communityMode && securityLevel != QStringLiteral("noAuthNoPriv");
    const bool privacyEnabled = !communityMode && securityLevel == QStringLiteral("authPriv");

    if (m_snmpWidgets.v3AuthProtocolCombo != nullptr) {
        m_snmpWidgets.v3AuthProtocolCombo->setEnabled(authEnabled);
    }
    if (m_snmpWidgets.v3AuthPasswordEdit != nullptr) {
        m_snmpWidgets.v3AuthPasswordEdit->setEnabled(authEnabled);
    }
    if (m_snmpWidgets.v3PrivacyProtocolCombo != nullptr) {
        m_snmpWidgets.v3PrivacyProtocolCombo->setEnabled(privacyEnabled);
    }
    if (m_snmpWidgets.v3PrivacyPasswordEdit != nullptr) {
        m_snmpWidgets.v3PrivacyPasswordEdit->setEnabled(privacyEnabled);
    }
    if (auto* currentPage = m_snmpWidgets.securityStack->currentWidget(); currentPage != nullptr) {
        const QSize targetSize = currentPage->sizeHint().expandedTo(QSize(0, 19));
        m_snmpWidgets.securityStack->setFixedWidth(targetSize.width());
        const int targetHeight = qMax(19, targetSize.height());
        m_snmpWidgets.securityStack->setFixedHeight(targetHeight);
    }
}

void MainWindow::applySnmpTableFilter() {
    if (m_snmpWidgets.table == nullptr) {
        return;
    }
    const QString needle = m_snmpWidgets.filterEdit == nullptr ? QString() : m_snmpWidgets.filterEdit->text().trimmed().toLower();
    for (int row = 0; row < m_snmpWidgets.table->rowCount(); ++row) {
        bool visible = needle.isEmpty();
        if (!visible) {
            QStringList parts;
            for (int column = 0; column < m_snmpWidgets.table->columnCount(); ++column) {
                const auto* item = m_snmpWidgets.table->item(row, column);
                if (item != nullptr) {
                    parts.append(item->text());
                }
            }
            visible = parts.join(QLatin1Char(' ')).toLower().contains(needle);
        }
        m_snmpWidgets.table->setRowHidden(row, !visible);
    }
}

void MainWindow::persistSnmpSettingsFromUi() {
    if (m_settings == nullptr) {
        return;
    }
    const nt::SessionProfile profile = currentSnmpProfile();
    auto section = m_settings->section(QStringLiteral("snmp"));
    section.insert(QStringLiteral("host"), profile.host);
    section.insert(QStringLiteral("port"), static_cast<int>(profile.port == 0 ? 161 : profile.port));
    section.insert(QStringLiteral("version"), profile.protocolVersion);
    section.insert(QStringLiteral("read_community"), profile.snmpReadCommunity);
    section.insert(QStringLiteral("write_community"), profile.snmpWriteCommunity);
    section.insert(QStringLiteral("v3_user"), profile.snmpV3User);
    section.insert(QStringLiteral("v3_security_level"), profile.snmpV3SecurityLevel);
    section.insert(QStringLiteral("v3_auth_protocol"), profile.snmpV3AuthProtocol);
    section.insert(QStringLiteral("v3_auth_password"), profile.snmpV3AuthPassword);
    section.insert(QStringLiteral("v3_privacy_protocol"), profile.snmpV3PrivacyProtocol);
    section.insert(QStringLiteral("v3_privacy_password"), profile.snmpV3PrivacyPassword);
    section.insert(QStringLiteral("base_oid"), QStringLiteral(".1"));
    m_settings->setSection(QStringLiteral("snmp"), section);
    m_settings->save();
}

QStringList MainWindow::currentSnmpAuthArgs(bool forWrite, QString* errorText) const {
    auto fail = [&](const QString& message) {
        if (errorText != nullptr) {
            *errorText = message;
        }
        return QStringList{};
    };

    if (m_snmpWidgets.versionCombo == nullptr) {
        return fail(uiText(m_settings, "SNMP-страница еще не инициализирована.", "SNMP page is not initialized yet."));
    }

    const QString version = comboValue(m_snmpWidgets.versionCombo);
    QStringList args {QStringLiteral("-v"), version};
    if (snmpUsesCommunity(version)) {
        const QString readCommunity = m_snmpWidgets.communityEdit != nullptr ? m_snmpWidgets.communityEdit->text().trimmed() : QString();
        const QString writeCommunity = m_snmpWidgets.writeCommunityEdit != nullptr ? m_snmpWidgets.writeCommunityEdit->text().trimmed() : QString();
        const QString community = forWrite && !writeCommunity.isEmpty() ? writeCommunity : readCommunity;
        if (community.isEmpty()) {
            return fail(
                forWrite
                    ? uiText(m_settings, "Укажите community для записи.", "Enter write community.")
                    : uiText(m_settings, "Укажите community для чтения.", "Enter read community.")
            );
        }
        args << QStringLiteral("-c") << community;
        return args;
    }

    const QString user = m_snmpWidgets.v3UserEdit != nullptr ? m_snmpWidgets.v3UserEdit->text().trimmed() : QString();
    const QString securityLevel = m_snmpWidgets.v3SecurityLevelCombo != nullptr ? comboValue(m_snmpWidgets.v3SecurityLevelCombo) : QStringLiteral("noAuthNoPriv");
    const QString authProtocol = m_snmpWidgets.v3AuthProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3AuthProtocolCombo) : QStringLiteral("SHA");
    const QString authPassword = m_snmpWidgets.v3AuthPasswordEdit != nullptr ? m_snmpWidgets.v3AuthPasswordEdit->text() : QString();
    const QString privacyProtocol = m_snmpWidgets.v3PrivacyProtocolCombo != nullptr ? comboValue(m_snmpWidgets.v3PrivacyProtocolCombo) : QStringLiteral("AES");
    const QString privacyPassword = m_snmpWidgets.v3PrivacyPasswordEdit != nullptr ? m_snmpWidgets.v3PrivacyPasswordEdit->text() : QString();

    if (user.isEmpty()) {
        return fail(uiText(m_settings, "Укажите SNMPv3 user.", "Enter SNMPv3 user."));
    }

    args << QStringLiteral("-l") << securityLevel
         << QStringLiteral("-u") << user;

    if (securityLevel == QStringLiteral("authNoPriv") || securityLevel == QStringLiteral("authPriv")) {
        if (authPassword.trimmed().isEmpty()) {
            return fail(uiText(m_settings, "Укажите пароль аутентификации SNMPv3.", "Enter SNMPv3 authentication password."));
        }
        args << QStringLiteral("-a") << authProtocol
             << QStringLiteral("-A") << authPassword;
    }

    if (securityLevel == QStringLiteral("authPriv")) {
        if (privacyPassword.trimmed().isEmpty()) {
            return fail(uiText(m_settings, "Укажите пароль приватности SNMPv3.", "Enter SNMPv3 privacy password."));
        }
        args << QStringLiteral("-x") << privacyProtocol
             << QStringLiteral("-X") << privacyPassword;
    }

    return args;
}

void MainWindow::loadSnmpOidList() {
    if (m_snmpWidgets.hostEdit == nullptr || m_snmpWidgets.table == nullptr) {
        return;
    }

    const QString host = m_snmpWidgets.hostEdit->text().trimmed();
    const QString baseOid = QStringLiteral(".1");
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    QString authError;
    const QStringList authArgs = currentSnmpAuthArgs(false, &authError);
    if (authArgs.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), authError);
        return;
    }

    persistSnmpSettingsFromUi();

    const QString snmpwalkPath = executableToolPath(QStringLiteral("snmpwalk"));
    if (snmpwalkPath.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), missingToolText(m_settings, QStringLiteral("snmpwalk")));
        return;
    }

    if (m_snmpWidgets.statusLabel != nullptr) {
        m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
        m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Полный SNMP walk...", "Full SNMP walk..."));
    }
    if (m_snmpWidgets.loadButton != nullptr) {
        m_snmpWidgets.loadButton->setEnabled(false);
    }
    if (m_snmpWidgets.communityLoadButton != nullptr) {
        m_snmpWidgets.communityLoadButton->setEnabled(false);
    }

    auto* process = new QProcess(this);
    configureSnmpProcessEnvironment(process, snmpwalkPath);
    QPointer<QProcess> processGuard(process);
    QTimer::singleShot(90000, process, [processGuard]() {
        if (processGuard != nullptr && processGuard->state() != QProcess::NotRunning) {
            processGuard->setProperty("networktools_timeout", true);
            processGuard->kill();
        }
    });
    QStringList args = authArgs;
    args << QStringLiteral("%1:%2").arg(host).arg(m_snmpWidgets.portSpin->value()) << baseOid;

    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError) {
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (m_snmpWidgets.communityLoadButton != nullptr) {
            m_snmpWidgets.communityLoadButton->setEnabled(true);
        }
        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Не удалось запустить snmpwalk.", "Failed to start snmpwalk."));
        }
        process->deleteLater();
    });

    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this, process, baseOid](int exitCode, QProcess::ExitStatus exitStatus) {
        const QString stdOut = QString::fromUtf8(process->readAllStandardOutput());
        const QString stdErr = QString::fromUtf8(process->readAllStandardError()).trimmed();
        const bool timedOut = process->property("networktools_timeout").toBool();
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (m_snmpWidgets.communityLoadButton != nullptr) {
            m_snmpWidgets.communityLoadButton->setEnabled(true);
        }

        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
                m_snmpWidgets.statusLabel->setText(timedOut
                    ? uiText(m_settings, "SNMP-опрос превысил таймаут.", "SNMP walk timed out.")
                    : stdErr.isEmpty()
                    ? uiText(m_settings, "SNMP-опрос завершился с ошибкой.", "SNMP walk failed.")
                    : stdErr);
            }
            process->deleteLater();
            return;
        }

        const QStringList lines = stdOut.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
        m_snmpTablePopulating = true;
        m_snmpWidgets.table->setRowCount(0);
        int inserted = 0;
        for (const QString& line : lines) {
            const auto parsed = parseSnmpLine(line);
            if (!parsed.valid) {
                continue;
            }
            const int row = m_snmpWidgets.table->rowCount();
            m_snmpWidgets.table->insertRow(row);

            auto* oidItem = new QTableWidgetItem(parsed.oid);
            oidItem->setFlags(oidItem->flags() & ~Qt::ItemIsEditable);
            oidItem->setToolTip(parsed.oid);

            const QString objectDescription = snmpObjectDescription(parsed.oid);
            auto* descItem = new QTableWidgetItem(describeOidLabel(m_settings, parsed.oid));
            descItem->setFlags(descItem->flags() & ~Qt::ItemIsEditable);
            if (!objectDescription.isEmpty()) {
                descItem->setToolTip(objectDescription);
            }

            auto* typeItem = new QTableWidgetItem(snmpTypeDisplayText(parsed.rawType));
            typeItem->setData(Qt::UserRole, parsed.rawType);
            typeItem->setFlags(typeItem->flags() & ~Qt::ItemIsEditable);
            typeItem->setTextAlignment(Qt::AlignCenter);
            if (!objectDescription.isEmpty()) {
                typeItem->setToolTip(objectDescription);
            }

            auto* valueItem = new QTableWidgetItem(snmpValueDisplayText(parsed.rawType, parsed.value));
            valueItem->setData(Qt::UserRole, parsed.rawType);
            valueItem->setData(Qt::UserRole + 1, snmpValueDisplayText(parsed.rawType, parsed.value));
            valueItem->setToolTip(parsed.value);

            m_snmpWidgets.table->setItem(row, 0, oidItem);
            m_snmpWidgets.table->setItem(row, 1, descItem);
            m_snmpWidgets.table->setItem(row, 2, typeItem);
            m_snmpWidgets.table->setItem(row, 3, valueItem);
            ++inserted;
        }
        m_snmpTablePopulating = false;

        if (inserted > 0) {
            m_snmpWidgets.table->selectRow(0);
            applySnmpTableFilter();
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#6fd27f;"));
                m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Доступных OID: %1", "Accessible OIDs: %1").arg(inserted));
            }
        } else if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "OID по этому запросу не найдены.", "No OIDs found for this query."));
        }
        process->deleteLater();
    });

    process->start(snmpwalkPath, args);
}

void MainWindow::applySnmpSelectedValue() {
    if (m_snmpWidgets.table == nullptr) {
        return;
    }
    const int row = m_snmpWidgets.table->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Сначала выберите строку OID.", "Select an OID row first."));
        return;
    }

    auto* oidItem = m_snmpWidgets.table->item(row, 0);
    auto* typeItem = m_snmpWidgets.table->item(row, 2);
    auto* valueItem = m_snmpWidgets.table->item(row, 3);
    if (oidItem == nullptr || typeItem == nullptr || valueItem == nullptr) {
        return;
    }

    const QString host = m_snmpWidgets.hostEdit->text().trimmed();
    const QString rawType = typeItem->data(Qt::UserRole).toString();
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    QString authError;
    const QString typeToken = snmpSetTypeToken(rawType);
    const QStringList authArgs = currentSnmpAuthArgs(true, &authError);
    if (authArgs.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), authError);
        return;
    }

    if (typeToken.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Этот тип OID нельзя изменить автоматически.", "This OID type cannot be changed automatically."));
        return;
    }

    const QString snmpsetPath = executableToolPath(QStringLiteral("snmpset"));
    if (snmpsetPath.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), missingToolText(m_settings, QStringLiteral("snmpset")));
        return;
    }

    const QString previousValue = valueItem->data(Qt::UserRole + 1).toString();
    const QString newValue = valueItem->text().trimmed();
    if (newValue.isEmpty() && typeToken != QStringLiteral("s")) {
        QMessageBox::warning(this, QStringLiteral("SNMP"), uiText(m_settings, "Поле значения пустое.", "Value field is empty."));
        m_snmpTablePopulating = true;
        valueItem->setText(previousValue);
        m_snmpTablePopulating = false;
        return;
    }

    if (m_snmpWidgets.loadButton != nullptr) {
        m_snmpWidgets.loadButton->setEnabled(false);
    }
    if (m_snmpWidgets.communityLoadButton != nullptr) {
        m_snmpWidgets.communityLoadButton->setEnabled(false);
    }
    if (m_snmpWidgets.statusLabel != nullptr) {
        m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#f2c36a;"));
        m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Изменение OID...", "Updating OID..."));
    }

    auto* process = new QProcess(this);
    configureSnmpProcessEnvironment(process, snmpsetPath);
    QPointer<QProcess> processGuard(process);
    QTimer::singleShot(15000, process, [processGuard]() {
        if (processGuard != nullptr && processGuard->state() != QProcess::NotRunning) {
            processGuard->setProperty("networktools_timeout", true);
            processGuard->kill();
        }
    });
    QStringList args = authArgs;
    args << QStringLiteral("%1:%2").arg(host).arg(m_snmpWidgets.portSpin->value())
         << oidItem->text()
         << typeToken
         << newValue;

    connect(process, &QProcess::errorOccurred, this, [this, process, row, previousValue](QProcess::ProcessError) {
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (m_snmpWidgets.communityLoadButton != nullptr) {
            m_snmpWidgets.communityLoadButton->setEnabled(true);
        }
        if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
            m_snmpTablePopulating = true;
            valueItem->setText(previousValue);
            m_snmpTablePopulating = false;
        }
        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Не удалось запустить snmpset.", "Failed to start snmpset."));
        }
        process->deleteLater();
    });

    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this, process, row, previousValue](int exitCode, QProcess::ExitStatus exitStatus) {
        const QString stdOut = QString::fromUtf8(process->readAllStandardOutput());
        const QString stdErr = QString::fromUtf8(process->readAllStandardError()).trimmed();
        const bool timedOut = process->property("networktools_timeout").toBool();
        if (m_snmpWidgets.loadButton != nullptr) {
            m_snmpWidgets.loadButton->setEnabled(true);
        }
        if (m_snmpWidgets.communityLoadButton != nullptr) {
            m_snmpWidgets.communityLoadButton->setEnabled(true);
        }

        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
                m_snmpTablePopulating = true;
                valueItem->setText(previousValue);
                m_snmpTablePopulating = false;
            }
            if (m_snmpWidgets.statusLabel != nullptr) {
                m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#ef7b7b;"));
                m_snmpWidgets.statusLabel->setText(timedOut
                    ? uiText(m_settings, "SNMP-запись превысила таймаут.", "SNMP set timed out.")
                    : stdErr.isEmpty()
                    ? uiText(m_settings, "Не удалось изменить значение OID.", "Failed to update OID value.")
                    : stdErr);
            }
            process->deleteLater();
            return;
        }

        const QStringList lines = stdOut.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
        for (const QString& line : lines) {
            const auto parsed = parseSnmpLine(line);
            if (!parsed.valid) {
                continue;
            }
            m_snmpTablePopulating = true;
            if (auto* typeItem = m_snmpWidgets.table->item(row, 2)) {
                typeItem->setText(snmpTypeDisplayText(parsed.rawType));
                typeItem->setData(Qt::UserRole, parsed.rawType);
            }
            if (auto* valueItem = m_snmpWidgets.table->item(row, 3)) {
                valueItem->setText(snmpValueDisplayText(parsed.rawType, parsed.value));
                valueItem->setData(Qt::UserRole, parsed.rawType);
                valueItem->setData(Qt::UserRole + 1, snmpValueDisplayText(parsed.rawType, parsed.value));
                valueItem->setToolTip(parsed.value);
            }
            m_snmpTablePopulating = false;
            break;
        }

        if (m_snmpWidgets.statusLabel != nullptr) {
            m_snmpWidgets.statusLabel->setStyleSheet(QStringLiteral("color:#6fd27f;"));
            m_snmpWidgets.statusLabel->setText(uiText(m_settings, "Значение OID обновлено.", "OID value updated."));
        }
        process->deleteLater();
    });

    process->start(snmpsetPath, args);
}

void MainWindow::handleSnmpValueEdited(QTableWidgetItem* item) {
    if (m_snmpTablePopulating || item == nullptr || item->column() != 3) {
        return;
    }
    const QString previousValue = item->data(Qt::UserRole + 1).toString();
    const QString currentValue = item->text().trimmed();
    if (previousValue == currentValue) {
        return;
    }
    if (m_snmpWidgets.table != nullptr) {
        m_snmpWidgets.table->setCurrentItem(item);
    }
    applySnmpSelectedValue();
}

void MainWindow::loadSessionProfiles(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    widgets.profiles->clear();
    const auto profiles = m_settings->sessionProfiles(kind, defaultPort);
    for (const auto& profile : profiles) {
        const QString subtitle = profile.username.trimmed().isEmpty()
            ? QStringLiteral("%1:%2").arg(profile.host).arg(profile.port)
            : QStringLiteral("%1@%2:%3").arg(profile.username, profile.host).arg(profile.port);
        auto* item = new QListWidgetItem(QStringLiteral("%1\n%2").arg(profile.name, subtitle));
        item->setData(Qt::UserRole, QVariant::fromValue(profile));
        widgets.profiles->addItem(item);
    }
    if (widgets.profiles->count() > 0) {
        widgets.profiles->setCurrentRow(0);
    } else {
        newSessionProfile(widgets, defaultPort);
    }
}

void MainWindow::applySessionProfile(const nt::SessionProfile& profile, SessionWidgets& widgets) {
    widgets.nameEdit->setText(profile.name);
    widgets.hostEdit->setText(profile.host);
    widgets.portSpin->setValue(profile.port);
    widgets.userEdit->setText(profile.username);
    widgets.passEdit->setText(profile.password);
}

nt::SessionProfile MainWindow::currentSessionProfile(const SessionWidgets& widgets, quint16 defaultPort) const {
    nt::SessionProfile profile;
    profile.name = widgets.nameEdit->text().trimmed();
    profile.host = widgets.hostEdit->text().trimmed();
    profile.port = static_cast<quint16>(widgets.portSpin->value());
    profile.username = widgets.userEdit->text().trimmed();
    profile.password = widgets.passEdit->text();
    if (profile.port == 0) {
        profile.port = defaultPort;
    }
    if (profile.name.isEmpty()) {
        profile.name = QStringLiteral("%1:%2").arg(profile.host, QString::number(profile.port));
    }
    return profile;
}

void MainWindow::saveSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto profile = currentSessionProfile(widgets, defaultPort);
    if (profile.host.isEmpty()) {
        QMessageBox::warning(this, kind.toUpper(), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }

    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& item) {
        return item.name == profile.name;
    }), profiles.end());
    profiles.prepend(profile);
    while (profiles.size() > 80) {
        profiles.removeLast();
    }

    m_settings->storeSessionProfiles(kind, profiles, profile);
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::deleteSessionProfile(const QString& kind, SessionWidgets& widgets, quint16 defaultPort) {
    const auto* item = widgets.profiles->currentItem();
    if (item == nullptr) {
        return;
    }
    const auto current = item->data(Qt::UserRole).value<nt::SessionProfile>();
    QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, defaultPort);
    profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return profile.name == current.name;
    }), profiles.end());
    m_settings->storeSessionProfiles(kind, profiles, currentSessionProfile(widgets, defaultPort));
    m_settings->save();
    loadSessionProfiles(kind, widgets, defaultPort);
}

void MainWindow::newSessionProfile(SessionWidgets& widgets, quint16 defaultPort) {
    widgets.nameEdit->clear();
    widgets.hostEdit->clear();
    widgets.portSpin->setValue(defaultPort);
    widgets.userEdit->clear();
    widgets.passEdit->clear();
}
