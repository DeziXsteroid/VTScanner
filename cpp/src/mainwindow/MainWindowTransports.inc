void MainWindow::sendHttpRequest() {
    if (m_requestUrlEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("HTTP / REQ"), uiText(m_settings, "Поле URL пустое.", "URL field is empty."));
        return;
    }

    bool parseFailed = false;
    auto parseObject = [this, &parseFailed](QPlainTextEdit* edit, const QString& title, bool allowEmpty = true) -> QJsonObject {
        QJsonParseError error;
        const QByteArray data = edit->toPlainText().trimmed().toUtf8();
        if (data.isEmpty() && allowEmpty) {
            return {};
        }
        const auto document = QJsonDocument::fromJson(data, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            parseFailed = true;
            QMessageBox::warning(
                this,
                QStringLiteral("HTTP / REQ"),
                uiText(m_settings, "%1 должны быть JSON-объектом.", "%1 must be a JSON object.").arg(title)
            );
            return {};
        }
        return document.object();
    };

    nt::HttpRequestSpec spec;
    spec.method = m_requestMethodCombo->currentText();
    spec.url = m_requestUrlEdit->text().trimmed();
    if (!spec.url.contains(QRegularExpression(QStringLiteral("^[a-zA-Z][a-zA-Z0-9+.-]*://")))) {
        spec.url.prepend(QStringLiteral("http://"));
    }
    spec.headers = parseObject(m_requestHeadersEdit, uiText(m_settings, "Заголовки", "Headers"));
    spec.params = parseObject(m_requestParamsEdit, uiText(m_settings, "Параметры", "Params"));
    if (parseFailed) {
        return;
    }
    spec.body = m_requestBodyEdit->toPlainText().toUtf8();
    spec.username = m_requestUserEdit->text().trimmed();
    spec.password = m_requestPassEdit->text();
    spec.timeoutSec = m_requestTimeoutSpin->value();

    QTextCursor cursor(m_requestResponseEdit->document());
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat textFormat;
    textFormat.setFont(fixedFont());
    textFormat.setForeground(isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6"));

    cursor.insertText(QStringLiteral("Network Tools -> %1 [%2]\n").arg(spec.url, spec.method.toUpper()), textFormat);
    m_requestResponseEdit->setTextCursor(cursor);
    m_requestResponseEdit->ensureCursorVisible();

    QJsonArray history = m_settings->value(QStringLiteral("http_history"), QJsonArray{}).toArray();
    QJsonObject item {
        {QStringLiteral("method"), spec.method.toUpper()},
        {QStringLiteral("url"), spec.url},
        {QStringLiteral("headers"), m_requestHeadersEdit->toPlainText()},
        {QStringLiteral("params"), m_requestParamsEdit->toPlainText()},
        {QStringLiteral("body"), m_requestBodyEdit->toPlainText()},
        {QStringLiteral("username"), spec.username},
        {QStringLiteral("timeout"), spec.timeoutSec},
    };
    QJsonArray compacted;
    compacted.append(item);
    for (const auto& value : history) {
        if (!value.isObject()) {
            continue;
        }
        const auto object = value.toObject();
        if (object.value(QStringLiteral("method")).toString() == item.value(QStringLiteral("method")).toString()
            && object.value(QStringLiteral("url")).toString() == item.value(QStringLiteral("url")).toString()
            && object.value(QStringLiteral("body")).toString() == item.value(QStringLiteral("body")).toString()) {
            continue;
        }
        compacted.append(object);
        if (compacted.size() >= 40) {
            break;
        }
    }
    m_settings->setValue(QStringLiteral("http_history"), compacted);
    m_settings->save();
    m_http->send(spec);
}

void MainWindow::openHttpHistory() {
    const QJsonArray history = m_settings->value(QStringLiteral("http_history"), QJsonArray{}).toArray();
    if (history.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("HTTP History"), uiText(m_settings, "История запросов пока пуста.", "Request history is empty."));
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(uiText(m_settings, "История HTTP", "HTTP History"));
    dialog.resize(760, 440);

    auto* root = new QVBoxLayout(&dialog);
    auto* list = new QListWidget(&dialog);
    root->addWidget(list, 1);

    for (const auto& value : history) {
        if (!value.isObject()) {
            continue;
        }
        const auto object = value.toObject();
        const QString method = object.value(QStringLiteral("method")).toString();
        const QString url = object.value(QStringLiteral("url")).toString();
        auto* item = new QListWidgetItem(QStringLiteral("%1  %2").arg(method, url));
        item->setData(Qt::UserRole, object);
        item->setForeground(httpMethodColor(method));
        QFont font = item->font();
        font.setBold(true);
        item->setFont(font);
        list->addItem(item);
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto* applyButton = buttons->addButton(uiText(m_settings, "Повторить", "Reuse"), QDialogButtonBox::AcceptRole);
    root->addWidget(buttons);

    const auto applySelection = [this, list, &dialog]() {
        auto* item = list->currentItem();
        if (item == nullptr) {
            return;
        }
        const QJsonObject object = item->data(Qt::UserRole).toJsonObject();
        m_requestMethodCombo->setCurrentText(object.value(QStringLiteral("method")).toString(QStringLiteral("GET")));
        m_requestUrlEdit->setText(object.value(QStringLiteral("url")).toString());
        m_requestHeadersEdit->setPlainText(object.value(QStringLiteral("headers")).toString());
        m_requestParamsEdit->setPlainText(object.value(QStringLiteral("params")).toString());
        m_requestBodyEdit->setPlainText(object.value(QStringLiteral("body")).toString());
        m_requestUserEdit->setText(object.value(QStringLiteral("username")).toString());
        m_requestPassEdit->clear();
        m_requestTimeoutSpin->setValue(object.value(QStringLiteral("timeout")).toInt(10));
        dialog.accept();
    };

    connect(applyButton, &QPushButton::clicked, &dialog, applySelection);
    connect(list, &QListWidget::itemDoubleClicked, &dialog, [applySelection](QListWidgetItem*) { applySelection(); });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}

#ifndef Q_OS_ANDROID
void MainWindow::refreshSerialPorts() {
    if (m_serialWidgets.portCombo == nullptr) {
        return;
    }
    const QString current = m_serialWidgets.portCombo->currentData().toString();
    const QString preferred = current.isEmpty()
        ? m_settings->section(QStringLiteral("serial")).value(QStringLiteral("port_name")).toString()
        : current;
    auto ports = QSerialPortInfo::availablePorts();
    std::sort(ports.begin(), ports.end(), [](const auto& left, const auto& right) {
        const bool leftCu = left.portName().startsWith(QStringLiteral("cu."));
        const bool rightCu = right.portName().startsWith(QStringLiteral("cu."));
        if (leftCu != rightCu) {
            return leftCu;
        }
        return left.portName().toLower() < right.portName().toLower();
    });
    QList<QPair<QString, QString>> entries;
    if (ports.isEmpty()) {
        entries.append({uiText(m_settings, "(портов нет)", "(no ports)"), QString()});
    } else {
        for (const auto& port : ports) {
            const QString label = QStringLiteral("%1 - %2").arg(port.portName(), port.description().trimmed().isEmpty() ? port.portName() : port.description());
            entries.append({label, port.portName()});
        }
    }

    bool changed = m_serialWidgets.portCombo->count() != entries.size();
    for (int i = 0; !changed && i < entries.size(); ++i) {
        changed = m_serialWidgets.portCombo->itemText(i) != entries.at(i).first
            || m_serialWidgets.portCombo->itemData(i).toString() != entries.at(i).second;
    }
    if (!changed) {
        return;
    }

    QSignalBlocker blocker(m_serialWidgets.portCombo);
    m_serialWidgets.portCombo->clear();
    for (const auto& entry : entries) {
        m_serialWidgets.portCombo->addItem(entry.first, entry.second);
    }
    const int index = m_serialWidgets.portCombo->findData(preferred);
    m_serialWidgets.portCombo->setCurrentIndex(index >= 0 ? index : 0);
}

void MainWindow::toggleSerial() {
    if (m_serialSession->isOpen()) {
        m_serialSession->close();
        return;
    }
    const QString portName = m_serialWidgets.portCombo->currentData().toString();
    if (portName.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Serial"), uiText(m_settings, "Порт не выбран.", "Port is not selected."));
        return;
    }
    QString error;
    const bool ok = m_serialSession->open(
        portName,
        m_serialWidgets.baudCombo->currentText().toInt(),
        m_serialWidgets.bitsCombo->currentText().toInt(),
        comboValue(m_serialWidgets.parityCombo),
        m_serialWidgets.stopBitsCombo->currentText(),
        comboValue(m_serialWidgets.flowControlCombo),
        &error
    );
    if (!ok) {
        QMessageBox::critical(this, QStringLiteral("Serial"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("serial"));
    section.insert(QStringLiteral("port_name"), portName);
    section.insert(QStringLiteral("baud"), m_serialWidgets.baudCombo->currentText());
    section.insert(QStringLiteral("data_bits"), m_serialWidgets.bitsCombo->currentText());
    section.insert(QStringLiteral("parity"), comboValue(m_serialWidgets.parityCombo));
    section.insert(QStringLiteral("stop_bits"), m_serialWidgets.stopBitsCombo->currentText());
    section.insert(QStringLiteral("flow_control"), comboValue(m_serialWidgets.flowControlCombo));
    m_settings->setSection(QStringLiteral("serial"), section);
    m_settings->save();
    appendTrafficEntry(
        m_serialWidgets.outputBox,
        QColor("#b0bac5"),
        QStringLiteral("INFO"),
        isEnglishUi(m_settings)
            ? QStringLiteral("Connected %1 @ %2").arg(portName, m_serialWidgets.baudCombo->currentText())
            : QStringLiteral("Подключено %1 @ %2").arg(portName, m_serialWidgets.baudCombo->currentText())
    );
}
#endif

void MainWindow::toggleTcp() {
    if (m_tcpSession->isConnected()) {
        m_tcpSession->close();
        return;
    }
    const QString host = m_tcpWidgets.hostEdit->text().trimmed();
    if (host.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("TCP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
        return;
    }
    m_tcpWidgets.outputBox->clear();
    quint16 remotePort = static_cast<quint16>(m_tcpWidgets.portSpin->value());
    if (m_tcpWidgets.autoPortCheck != nullptr && m_tcpWidgets.autoPortCheck->isChecked()) {
        appendTrafficEntry(
            m_tcpWidgets.outputBox,
            QColor("#b0bac5"),
            QStringLiteral("INFO"),
            uiText(m_settings, "Поиск открытого TCP-порта...", "Searching open TCP port...")
        );
        const quint16 detectedPort = detectOpenTcpPort(host, remotePort);
        if (detectedPort == 0) {
            appendTrafficEntry(
                m_tcpWidgets.outputBox,
                QColor("#d8b45d"),
                QStringLiteral("WARN"),
                uiText(m_settings, "Автопорт TCP не найден, используется выбранный порт.", "TCP auto port was not found, using the selected port.")
            );
        } else {
            remotePort = detectedPort;
            m_tcpWidgets.portSpin->setValue(remotePort);
            appendTrafficEntry(
                m_tcpWidgets.outputBox,
                QColor("#7fda72"),
                QStringLiteral("INFO"),
                uiText(m_settings, "Найден TCP-порт %1", "Detected TCP port %1").arg(remotePort)
            );
        }
    }
    QString error;
    if (!m_tcpSession->open(
            host,
            remotePort,
            static_cast<quint16>(m_tcpWidgets.localPortSpin->value()),
            m_tcpWidgets.noDelayCheck->isChecked(),
            m_tcpWidgets.keepAliveCheck->isChecked(),
            &error)) {
        QMessageBox::critical(this, QStringLiteral("TCP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("tcp"));
    section.insert(QStringLiteral("host"), host);
    section.insert(QStringLiteral("port"), m_tcpWidgets.portSpin->value());
    section.insert(QStringLiteral("local_port"), m_tcpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("no_delay"), m_tcpWidgets.noDelayCheck->isChecked());
    section.insert(QStringLiteral("keep_alive"), m_tcpWidgets.keepAliveCheck->isChecked());
    section.insert(QStringLiteral("auto_port"), m_tcpWidgets.autoPortCheck != nullptr && m_tcpWidgets.autoPortCheck->isChecked());
    m_settings->setSection(QStringLiteral("tcp"), section);
    m_settings->save();
}

void MainWindow::toggleUdp() {
    if (m_udpSession->isOpen()) {
        m_udpSession->close();
        return;
    }
    const QString host = m_udpWidgets.hostEdit->text().trimmed();
    quint16 remotePort = static_cast<quint16>(m_udpWidgets.remotePortSpin->value());
    if (m_udpWidgets.autoPortCheck != nullptr && m_udpWidgets.autoPortCheck->isChecked()) {
        if (host.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("UDP"), uiText(m_settings, "Поле хоста пустое.", "Host field is empty."));
            return;
        }
        m_udpWidgets.outputBox->clear();
        appendTrafficEntry(
            m_udpWidgets.outputBox,
            QColor("#b0bac5"),
            QStringLiteral("INFO"),
            uiText(m_settings, "Поиск ответного UDP-порта...", "Searching responsive UDP port...")
        );
        const QByteArray probe = payloadFromText(m_udpWidgets.inputEdit != nullptr ? m_udpWidgets.inputEdit->text() : QString(), m_udpWidgets.hexCheck != nullptr && m_udpWidgets.hexCheck->isChecked());
        const quint16 detectedPort = detectResponsiveUdpPort(host, remotePort, probe);
        if (detectedPort == 0) {
            appendTrafficEntry(
                m_udpWidgets.outputBox,
                QColor("#d8b45d"),
                QStringLiteral("WARN"),
                uiText(m_settings, "Автопорт UDP не ответил, используется выбранный порт.", "UDP auto port did not respond, using the selected port.")
            );
        } else {
            remotePort = detectedPort;
            m_udpWidgets.remotePortSpin->setValue(remotePort);
            appendTrafficEntry(
                m_udpWidgets.outputBox,
                QColor("#7fda72"),
                QStringLiteral("INFO"),
                uiText(m_settings, "Найден UDP-порт %1", "Detected UDP port %1").arg(remotePort)
            );
        }
    }
    QString error;
    if (!m_udpSession->bind(static_cast<quint16>(m_udpWidgets.localPortSpin->value()), m_udpWidgets.reuseAddressCheck->isChecked(), &error)) {
        QMessageBox::critical(this, QStringLiteral("UDP"), error);
        return;
    }
    auto section = m_settings->section(QStringLiteral("udp"));
    section.insert(QStringLiteral("host"), host);
    section.insert(QStringLiteral("remote_port"), remotePort);
    section.insert(QStringLiteral("local_port"), m_udpWidgets.localPortSpin->value());
    section.insert(QStringLiteral("reuse_address"), m_udpWidgets.reuseAddressCheck->isChecked());
    section.insert(QStringLiteral("auto_port"), m_udpWidgets.autoPortCheck != nullptr && m_udpWidgets.autoPortCheck->isChecked());
    m_settings->setSection(QStringLiteral("udp"), section);
    m_settings->save();
    appendTrafficEntry(
        m_udpWidgets.outputBox,
        QColor("#b0bac5"),
        QStringLiteral("INFO"),
        isEnglishUi(m_settings)
            ? QStringLiteral("UDP open :%1").arg(m_udpSession->localPort())
            : QStringLiteral("Открыт UDP :%1").arg(m_udpSession->localPort())
    );
}

QByteArray MainWindow::payloadFromText(const QString& text, bool hexEnabled) {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }
    if (trimmed.contains(QStringLiteral("\\x"))) {
        QByteArray payload;
        const auto matches = QRegularExpression(QStringLiteral("\\\\x([0-9a-fA-F]{2})")).globalMatch(trimmed);
        auto it = matches;
        while (it.hasNext()) {
            const auto match = it.next();
            bool ok = false;
            const auto value = match.captured(1).toUInt(&ok, 16);
            if (ok) {
                payload.append(static_cast<char>(value));
            }
        }
        if (!payload.isEmpty()) {
            return payload;
        }
    }
    if (hexEnabled) {
        QByteArray payload;
        const auto parts = trimmed.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        bool allHex = !parts.isEmpty();
        for (const auto& part : parts) {
            bool ok = false;
            const auto value = part.toUInt(&ok, 16);
            if (!ok || part.size() > 2) {
                allHex = false;
                break;
            }
            payload.append(static_cast<char>(value));
        }
        if (allHex) {
            return payload;
        }
    }
    return trimmed.toUtf8();
}

QString MainWindow::displayBytes(const QByteArray& bytes, bool hexEnabled) {
    if (hexEnabled) {
        return QString::fromUtf8(bytes.toHex(' '));
    }
    return nt::TerminalSanitizer::sanitize(bytes);
}

QByteArray MainWindow::applyLineEnding(QByteArray payload, const QString& eolName, bool hexEnabled) {
    if (hexEnabled) {
        return payload;
    }
    const QString eolKey = normalizedEolKey(eolName);
    if (eolKey == QStringLiteral("cr")) {
        payload.append('\r');
    } else if (eolKey == QStringLiteral("lf")) {
        payload.append('\n');
    } else if (eolKey == QStringLiteral("crlf")) {
        payload.append("\r\n");
    }
    return payload;
}

void MainWindow::appendTrafficEntry(QTextEdit* box, const QColor& arrowColor, const QString& direction, const QString& payload, const QString& endpoint) {
    if (box == nullptr || payload.isEmpty()) {
        return;
    }
    QTextCursor cursor(box->document());
    cursor.movePosition(QTextCursor::End);

    QTextCharFormat arrowFormat;
    arrowFormat.setForeground(arrowColor);
    arrowFormat.setFont(fixedFont());
    arrowFormat.setFontWeight(QFont::Bold);

    QTextCharFormat textFormat;
    textFormat.setForeground(QColor("#eef2f6"));
    textFormat.setFont(fixedFont());

    QTextCharFormat metaFormat = textFormat;
    metaFormat.setForeground(QColor("#a7b2be"));

    cursor.insertText(QStringLiteral("➜ "), arrowFormat);
    cursor.insertText(direction, arrowFormat);
    if (!endpoint.isEmpty()) {
        cursor.insertText(QStringLiteral(" [%1]").arg(endpoint), metaFormat);
    }
    cursor.insertText(QStringLiteral("\n"), textFormat);
    cursor.insertText(payload, textFormat);
    cursor.insertText(QStringLiteral("\n\n"), textFormat);
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::loadQuickCommands(const QString& key, StreamWidgets& widgets) {
    const auto section = m_settings->section(key);
    const auto commands = section.value(QStringLiteral("quick_commands")).toArray();
    for (int i = 0; i < widgets.quickEdits.size(); ++i) {
        widgets.quickEdits[i]->setText(i < commands.size() ? commands.at(i).toString() : QString());
    }
    if (widgets.inputEdit != nullptr) {
        widgets.inputEdit->setText(section.value(QStringLiteral("draft")).toString());
    }
    if (widgets.eolCombo != nullptr) {
        setComboByData(widgets.eolCombo, normalizedEolKey(section.value(QStringLiteral("eol")).toString(QStringLiteral("none"))));
    }
}

void MainWindow::saveQuickCommands(const QString& key, const StreamWidgets& widgets) {
    auto section = m_settings->section(key);
    QJsonArray commands;
    for (auto* edit : widgets.quickEdits) {
        commands.append(edit == nullptr ? QString() : edit->text());
    }
    section.insert(QStringLiteral("quick_commands"), commands);
    if (widgets.inputEdit != nullptr) {
        section.insert(QStringLiteral("draft"), widgets.inputEdit->text());
    }
    if (widgets.eolCombo != nullptr) {
        section.insert(QStringLiteral("eol"), comboValue(widgets.eolCombo));
    }
    m_settings->setSection(key, section);
    m_settings->save();
}

void MainWindow::sendQuickCommand(const QString& key, StreamWidgets& widgets, int index) {
    if (index < 0 || index >= widgets.quickEdits.size() || widgets.inputEdit == nullptr) {
        return;
    }
    widgets.inputEdit->setText(widgets.quickEdits[index]->text());
    saveQuickCommands(key, widgets);
    if (key == QStringLiteral("serial")) {
#ifndef Q_OS_ANDROID
        sendSerialPayload();
#endif
    } else if (key == QStringLiteral("tcp")) {
        sendTcpPayload();
    } else if (key == QStringLiteral("udp")) {
        sendUdpPayload();
    }
}

#ifndef Q_OS_ANDROID
void MainWindow::sendSerialPayload() {
    QByteArray payload = payloadFromText(m_serialWidgets.inputEdit->text(), m_serialWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_serialWidgets.eolCombo), m_serialWidgets.hexCheck->isChecked());
    QString error;
    m_serialSession->sendBytes(payload, &error);
    if (!error.isEmpty()) {
        appendTrafficEntry(m_serialWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(m_serialWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_serialWidgets.hexCheck->isChecked()));
}
#endif

void MainWindow::sendTcpPayload() {
    QByteArray payload = payloadFromText(m_tcpWidgets.inputEdit->text(), m_tcpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    if (!m_tcpSession->isConnected()) {
        appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), uiText(m_settings, "TCP не подключен", "TCP is not connected"));
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_tcpWidgets.eolCombo), m_tcpWidgets.hexCheck->isChecked());
    m_tcpSession->sendBytes(payload);
    appendTrafficEntry(m_tcpWidgets.outputBox, QColor("#7fda72"), QStringLiteral("TX"), displayBytes(payload, m_tcpWidgets.hexCheck->isChecked()));
}

void MainWindow::sendUdpPayload() {
    QByteArray payload = payloadFromText(m_udpWidgets.inputEdit->text(), m_udpWidgets.hexCheck->isChecked());
    if (payload.isEmpty()) {
        return;
    }
    payload = applyLineEnding(payload, comboValue(m_udpWidgets.eolCombo), m_udpWidgets.hexCheck->isChecked());
    QString error;
    m_udpSession->sendDatagram(
        m_udpWidgets.hostEdit->text().trimmed(),
        static_cast<quint16>(m_udpWidgets.remotePortSpin->value()),
        payload,
        &error
    );
    if (!error.isEmpty()) {
        appendTrafficEntry(m_udpWidgets.outputBox, QColor("#d85d5d"), QStringLiteral("ERR"), error);
        return;
    }
    appendTrafficEntry(
        m_udpWidgets.outputBox,
        QColor("#7fda72"),
        QStringLiteral("TX"),
        displayBytes(payload, m_udpWidgets.hexCheck->isChecked()),
        QStringLiteral("%1:%2").arg(m_udpWidgets.hostEdit->text().trimmed()).arg(m_udpWidgets.remotePortSpin->value())
    );
}

void MainWindow::sendSessionTerminalBytes(QTextEdit* box, const QByteArray& bytes) {
    if (bytes.isEmpty()) {
        return;
    }
    if (box == m_sshWidgets.outputBox) {
        m_sshSession->sendBytes(bytes);
        return;
    }
    if (box == m_telnetWidgets.outputBox) {
        QByteArray payload = bytes;
        payload.replace("\r\n", "\n");
        payload.replace('\r', '\n');
        payload.replace("\n", "\r\n");
        m_telnetSession->sendBytes(payload);
    }
}

void MainWindow::appendSessionTerminalOutput(QTextEdit* box, const QString& text) {
    if (box == nullptr || text.isEmpty()) {
        return;
    }
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (format == nullptr) {
        return;
    }
    const QTextCharFormat baseFormat = box == m_sshWidgets.outputBox ? m_sshTerminalBaseFormat : m_telnetTerminalBaseFormat;
    removeSessionDraft(box);
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    QString chunk;
    const auto flushChunk = [&]() {
        if (!chunk.isEmpty()) {
            cursor.insertText(chunk, *format);
            chunk.clear();
        }
    };
    for (int i = 0; i < text.size(); ++i) {
        const QChar ch = text.at(i);
        if (ch == QChar::fromLatin1('\x1b')) {
            flushChunk();
            if (i + 1 >= text.size()) {
                break;
            }
            const QChar next = text.at(i + 1);
            if (next == QLatin1Char(']')) {
                int j = i + 2;
                while (j < text.size()) {
                    if (text.at(j) == QChar::fromLatin1('\x07')) {
                        break;
                    }
                    if (text.at(j) == QChar::fromLatin1('\x1b') && j + 1 < text.size() && text.at(j + 1) == QLatin1Char('\\')) {
                        ++j;
                        break;
                    }
                    ++j;
                }
                i = j;
                continue;
            }
            if (next != QLatin1Char('[')) {
                continue;
            }
            int j = i + 2;
            while (j < text.size()) {
                const QChar final = text.at(j);
                if (final.unicode() >= '@' && final.unicode() <= '~') {
                    break;
                }
                ++j;
            }
            if (j >= text.size()) {
                break;
            }
            const QString params = text.mid(i + 2, j - (i + 2));
            const QChar final = text.at(j);
            if (final == QLatin1Char('m')) {
                QList<int> codes;
                const auto parts = params.split(QLatin1Char(';'));
                for (const auto& part : parts) {
                    bool ok = false;
                    const int value = part.isEmpty() ? 0 : part.toInt(&ok);
                    codes.append(ok || part.isEmpty() ? value : 0);
                }
                applyTerminalSgr(codes, *format, baseFormat);
            } else if (final == QLatin1Char('J')) {
                const int mode = params.isEmpty() ? 0 : params.toInt();
                if (mode == 2 || mode == 3) {
                    box->clear();
                    cursor = box->textCursor();
                    *format = baseFormat;
                }
            } else if (final == QLatin1Char('K')) {
                cursor.movePosition(QTextCursor::EndOfBlock, QTextCursor::KeepAnchor);
                cursor.removeSelectedText();
            }
            i = j;
            continue;
        }
        if (ch == QChar::fromLatin1('\r')) {
            flushChunk();
            cursor.movePosition(QTextCursor::End);
            cursor.movePosition(QTextCursor::StartOfBlock, QTextCursor::KeepAnchor);
            cursor.removeSelectedText();
            continue;
        }
        if (ch == QChar::fromLatin1('\b')) {
            flushChunk();
            cursor.deletePreviousChar();
            continue;
        }
        if (ch == QLatin1Char('\n')) {
            flushChunk();
            cursor.insertText(QStringLiteral("\n"), *format);
            continue;
        }
        if (ch == QLatin1Char('\t')) {
            chunk.append(QStringLiteral("    "));
            continue;
        }
        if (ch.unicode() < 0x20) {
            continue;
        }
        chunk.append(ch);
    }
    flushChunk();
    box->setTextCursor(cursor);
    renderSessionDraft(box);
    box->ensureCursorVisible();
}

void MainWindow::renderSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    int* draftCursor = sessionDraftCursorForBox(box);
    QTextCharFormat* format = sessionTerminalFormatForBox(box);
    if (box == nullptr || draft == nullptr || draftCursor == nullptr || format == nullptr) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertText(*draft, *format);
    const int endPosition = cursor.position();
    cursor.setPosition(endPosition - (draft->size() - *draftCursor));
    box->setTextCursor(cursor);
    box->ensureCursorVisible();
}

void MainWindow::removeSessionDraft(QTextEdit* box) {
    QString* draft = sessionDraftForBox(box);
    if (box == nullptr || draft == nullptr || draft->isEmpty()) {
        return;
    }
    QTextCursor cursor = box->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.setPosition(cursor.position() - draft->size(), QTextCursor::KeepAnchor);
    cursor.removeSelectedText();
    box->setTextCursor(cursor);
}

QString* MainWindow::sessionDraftForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraft;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraft;
    }
    return nullptr;
}

int* MainWindow::sessionDraftCursorForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshDraftCursor;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetDraftCursor;
    }
    return nullptr;
}

QTextCharFormat* MainWindow::sessionTerminalFormatForBox(QTextEdit* box) {
    if (box == m_sshWidgets.outputBox) {
        return &m_sshTerminalFormat;
    }
    if (box == m_telnetWidgets.outputBox) {
        return &m_telnetTerminalFormat;
    }
    return nullptr;
}

void MainWindow::openSessionSettings(const QString& kind, SessionWidgets& widgets) {
    QDialog dialog(this);
    const bool isSsh = kind == QStringLiteral("ssh");
    dialog.setWindowTitle(isSsh ? QStringLiteral("SSH settings") : QStringLiteral("Telnet settings"));
    dialog.resize(isSsh ? QSize(560, 360) : QSize(360, 150));
    auto* root = new QVBoxLayout(&dialog);
    root->setContentsMargins(10, 10, 10, 10);
    root->setSpacing(8);
    auto* form = new QFormLayout();
    form->setVerticalSpacing(6);
    auto* colorCombo = new QComboBox(&dialog);
    colorCombo->addItem(QStringLiteral("Mint"), QStringLiteral("mint"));
    colorCombo->addItem(QStringLiteral("Green"), QStringLiteral("green"));
    colorCombo->addItem(QStringLiteral("Amber"), QStringLiteral("amber"));
    colorCombo->addItem(QStringLiteral("Cyan"), QStringLiteral("cyan"));
    colorCombo->addItem(QStringLiteral("White"), QStringLiteral("white"));
    const QString colorKey = kind + QStringLiteral("_terminal_color");
    colorCombo->setCurrentIndex(qMax(0, colorCombo->findData(m_settings->value(colorKey, QStringLiteral("mint")).toString(QStringLiteral("mint")))));
    form->addRow(uiText(m_settings, "Цвет терминала", "Terminal color"), colorCombo);
    root->addLayout(form);

    QPlainTextEdit* keyEdit = nullptr;
    if (isSsh) {
        auto* keyBox = new QGroupBox(uiText(m_settings, "SSH ключ профиля", "Profile SSH key"), &dialog);
        auto* keyLayout = new QVBoxLayout(keyBox);
        keyLayout->setContentsMargins(8, 8, 8, 8);
        keyLayout->setSpacing(6);
        keyEdit = new QPlainTextEdit(keyBox);
        keyEdit->setPlaceholderText(uiText(
            m_settings,
            "Вставьте приватный ключ или путь к файлу ключа. Если ключ задан, пароль можно не вводить.",
            "Paste a private key or a key file path. If a key is set, password can be empty."
        ));
        keyEdit->setMaximumHeight(150);
        keyEdit->setPlainText(currentSessionProfile(widgets, 22).sshPrivateKey);
        keyLayout->addWidget(keyEdit);
        auto* keyButtons = new QHBoxLayout();
        auto* chooseButton = new QPushButton(uiText(m_settings, "Выбрать файл", "Choose file"), keyBox);
        auto* clearButton = new QPushButton(uiText(m_settings, "Очистить", "Clear"), keyBox);
        keyButtons->addStretch(1);
        keyButtons->addWidget(chooseButton);
        keyButtons->addWidget(clearButton);
        keyLayout->addLayout(keyButtons);
        root->addWidget(keyBox);
        connect(chooseButton, &QPushButton::clicked, &dialog, [this, keyEdit]() {
            const QString path = QFileDialog::getOpenFileName(this, uiText(m_settings, "Выбрать SSH ключ", "Choose SSH key"));
            if (!path.isEmpty()) {
                keyEdit->setPlainText(QDir::toNativeSeparators(path));
            }
        });
        connect(clearButton, &QPushButton::clicked, keyEdit, &QPlainTextEdit::clear);
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    if (auto* okButton = buttons->button(QDialogButtonBox::Ok)) {
        okButton->setText(uiText(m_settings, "Сохранить", "Save"));
    }
    if (auto* cancelButton = buttons->button(QDialogButtonBox::Cancel)) {
        cancelButton->setText(uiText(m_settings, "Отмена", "Cancel"));
    }
    root->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    m_settings->setValue(colorKey, colorCombo->currentData().toString());
    if (isSsh && keyEdit != nullptr) {
        auto profile = currentSessionProfile(widgets, 22);
        profile.sshPrivateKey = keyEdit->toPlainText().trimmed();
        QList<nt::SessionProfile> profiles = m_settings->sessionProfiles(kind, 22);
        profiles.erase(std::remove_if(profiles.begin(), profiles.end(), [&](const auto& item) {
            return item.name == profile.name;
        }), profiles.end());
        profiles.prepend(profile);
        m_settings->storeSessionProfiles(kind, profiles, profile);
        loadSessionProfiles(kind, widgets, 22);
    }
    m_settings->save();
    refreshTerminalFormats();
}

void MainWindow::runPortSearch() {
    if (m_portSearchHostEdit == nullptr || m_portSearchTable == nullptr) {
        return;
    }
    QString input = property("port_search_input").toString().trimmed();
    setProperty("port_search_input", QString());
    if (input.isEmpty()) {
        input = m_portSearchHostEdit->text().trimmed();
        if (input.contains(QLatin1Char('-')) || input.contains(QStringLiteral(".."))) {
            QMessageBox::information(this, uiText(m_settings, "Поиск портов", "Search Ports"), uiText(m_settings, "Для диапазона используйте поля справа и кнопку \"Сканировать диапазон\".", "Use the range fields and the \"Scan range\" button for ranges."));
            return;
        }
    }
    const QStringList hosts = expandPortSearchTargets(input);
    if (hosts.isEmpty()) {
        return;
    }
    m_portSearchTable->setRowCount(0);
    if (m_portSearchButton != nullptr) {
        m_portSearchButton->setEnabled(false);
    }
    if (m_portSearchRangeButton != nullptr) {
        m_portSearchRangeButton->setEnabled(false);
    }
    if (m_portSearchStatusLabel != nullptr) {
        m_portSearchStatusLabel->setText(uiText(m_settings, "Сканирование портов...", "Scanning ports..."));
        m_portSearchStatusLabel->show();
    }
    QPointer<MainWindow> guard(this);
    (void)QtConcurrent::run([guard, hosts]() {
        const bool singleHost = hosts.size() == 1;
        const QList<quint16> ports = portSearchPorts(singleHost);
        const int timeoutMs = singleHost ? 28 : 8;
        QList<PortProbeJob> jobs;
        jobs.reserve(hosts.size() * ports.size());
        for (const QString& host : hosts) {
            for (const quint16 port : ports) {
                jobs.append(PortProbeJob {host, port, timeoutMs});
            }
        }
        const auto probed = QtConcurrent::blockingMapped(jobs, [](const PortProbeJob& job) {
            return qMakePair(job.host, probeTcpPort(job.host, job.port, job.timeoutMs));
        });
        QHash<QString, QList<PortProbeResult>> openResultsByHost;
        for (const auto& pair : probed) {
            if (pair.second.open) {
                openResultsByHost[pair.first].append(pair.second);
            }
        }
        QHash<QString, QString> hostMacs;
        for (const QString& host : hosts) {
            if (!openResultsByHost.contains(host)) {
                continue;
            }
            const QString mac = nt::NetworkScanService::lookupMac(host).trimmed();
            hostMacs.insert(host, mac.isEmpty() ? QStringLiteral("-") : mac);
        }
        QMetaObject::invokeMethod(guard.data(), [guard, hosts, openResultsByHost, hostMacs]() {
            if (guard == nullptr || guard->m_portSearchTable == nullptr) {
                return;
            }
            guard->m_portSearchTable->setRowCount(0);
            int openPortCount = 0;
            for (const QString& host : hosts) {
                const QList<PortProbeResult> hostResults = openResultsByHost.value(host);
                if (hostResults.isEmpty()) {
                    continue;
                }
                openPortCount += hostResults.size();
                const int row = guard->m_portSearchTable->rowCount();
                guard->m_portSearchTable->insertRow(row);
                const QString mac = hostMacs.value(host, QStringLiteral("-"));
                QStringList portValues;
                QStringList serviceValues;
                QStringList responseValues;
                for (const PortProbeResult& result : hostResults) {
                    portValues.append(QString::number(result.port));
                    serviceValues.append(result.service.trimmed().isEmpty()
                        ? QStringLiteral("%1/tcp").arg(result.port)
                        : QStringLiteral("%1 %2").arg(result.port).arg(result.service));
                    if (result.responseMs >= 0) {
                        responseValues.append(QStringLiteral("%1: %2 ms").arg(result.port).arg(result.responseMs));
                    }
                }
                const QStringList values {
                    host,
                    mac,
                    portValues.join(QStringLiteral(", ")),
                    serviceValues.join(QStringLiteral(", ")),
                    responseValues.isEmpty() ? uiText(guard->m_settings, "есть ответ", "responded") : responseValues.join(QStringLiteral(", ")),
                };
                for (int column = 0; column < values.size(); ++column) {
                    auto* item = new QTableWidgetItem(values.at(column));
                    item->setForeground(QBrush((column == 2 || column == 4)
                        ? QColor("#2f9e44")
                        : (guard->isLightTheme() ? QColor("#1f2730") : QColor("#eef2f6"))));
                    guard->m_portSearchTable->setItem(row, column, item);
                }
            }
            if (guard->m_portSearchStatusLabel != nullptr) {
                guard->m_portSearchStatusLabel->setText(
                    openPortCount > 0
                        ? uiText(guard->m_settings, "Найдено IP: %1 | открытых портов: %2", "Hosts found: %1 | open ports: %2")
                            .arg(guard->m_portSearchTable->rowCount())
                            .arg(openPortCount)
                        : uiText(guard->m_settings, "Ответов по TCP-портам нет", "No TCP port responses")
                );
                guard->m_portSearchStatusLabel->show();
            }
            if (guard->m_portSearchButton != nullptr) {
                guard->m_portSearchButton->setEnabled(true);
            }
            if (guard->m_portSearchRangeButton != nullptr) {
                guard->m_portSearchRangeButton->setEnabled(true);
            }
        });
    });
}

void MainWindow::refreshNetworkMonitoring() {
    if (m_networkMonitorTable == nullptr) {
        return;
    }
    QProcess process;
#ifdef Q_OS_WIN
    process.start(QStringLiteral("netstat"), {QStringLiteral("-ano")});
#else
    process.start(QStringLiteral("netstat"), {QStringLiteral("-tunp")});
#endif
    if (!process.waitForFinished(900)) {
        process.kill();
        return;
    }
    const QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
    m_networkMonitorTable->setRowCount(0);
    const QStringList lines = output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString& rawLine : lines) {
        const QString line = rawLine.simplified();
        if (!line.startsWith(QStringLiteral("TCP"), Qt::CaseInsensitive)
            && !line.startsWith(QStringLiteral("UDP"), Qt::CaseInsensitive)
            && !line.startsWith(QStringLiteral("tcp"), Qt::CaseInsensitive)
            && !line.startsWith(QStringLiteral("udp"), Qt::CaseInsensitive)) {
            continue;
        }
        const QStringList parts = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (parts.size() < 3) {
            continue;
        }
        const QString proto = parts.at(0).toUpper();
        const QString local = parts.value(1);
        const QString remote = parts.value(2);
        const bool isUdp = proto.startsWith(QStringLiteral("UDP"));
        const QString state = isUdp ? QStringLiteral("-") : parts.value(3, QStringLiteral("-"));
        const QString pid = isUdp ? parts.value(3, QStringLiteral("-")) : parts.value(4, QStringLiteral("-"));
        const int row = m_networkMonitorTable->rowCount();
        m_networkMonitorTable->insertRow(row);
        const QString direction = remote.contains(QStringLiteral("0.0.0.0")) || remote == QStringLiteral("*:*") ? QStringLiteral("listen") : QStringLiteral("flow");
        const QStringList values {proto, local, remote, state, pid, direction};
        for (int column = 0; column < values.size(); ++column) {
            auto* item = new QTableWidgetItem(values.at(column));
            if (direction == QStringLiteral("listen")) {
                item->setBackground(QBrush(isLightTheme() ? QColor("#e7eef7") : QColor("#172233")));
            } else if (proto.startsWith(QStringLiteral("UDP"))) {
                item->setBackground(QBrush(isLightTheme() ? QColor("#eef1df") : QColor("#222817")));
            }
            m_networkMonitorTable->setItem(row, column, item);
        }
    }
    if (m_networkMonitorStatusLabel != nullptr) {
        m_networkMonitorStatusLabel->setText(uiText(m_settings, "Соединений: %1", "Connections: %1").arg(m_networkMonitorTable->rowCount()));
    }
}

void MainWindow::showUpdateDialog(bool automatic) {
    checkForUpdates(automatic);
}

void MainWindow::checkForUpdates(bool automatic) {
    if (m_updateManager == nullptr) {
        return;
    }
    QNetworkRequest request(QUrl(QStringLiteral("https://api.github.com/repos/DeziXsteroid/Universal_Network_Tools/releases/latest")));
    request.setRawHeader("User-Agent", QByteArrayLiteral("NetworkToolsQt/1.2.1"));
    request.setRawHeader("Accept", QByteArrayLiteral("application/vnd.github+json"));
    auto* reply = m_updateManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, automatic]() {
        const QByteArray payload = reply->readAll();
        const bool networkOk = reply->error() == QNetworkReply::NoError;
        reply->deleteLater();
        if (!networkOk) {
            if (!automatic) {
                QMessageBox::information(this, QStringLiteral("Help and Updates"), uiText(m_settings, "Не удалось проверить обновления.", "Could not check for updates."));
            }
            return;
        }
        const auto doc = QJsonDocument::fromJson(payload);
        if (!doc.isObject()) {
            return;
        }
        const QJsonObject object = doc.object();
        const QString latest = object.value(QStringLiteral("tag_name")).toString(object.value(QStringLiteral("name")).toString()).trimmed();
        const QString latestClean = latest;
        const QString current = QCoreApplication::applicationVersion().trimmed();
        auto normalizeVersionText = [](QString value) {
            value = value.trimmed().toLower();
            if (value.startsWith(QLatin1Char('v'))) {
                value.remove(0, 1);
            }
            while (value.endsWith(QStringLiteral(".0"))) {
                value.chop(2);
            }
            return value;
        };
        const bool hasUpdate = !latestClean.isEmpty()
            && normalizeVersionText(latestClean) != normalizeVersionText(current);
        if (automatic && !hasUpdate) {
            return;
        }

        QDialog dialog(this);
        dialog.setWindowTitle(uiText(m_settings, "Помощь и обновления", "Help and Updates"));
        dialog.resize(380, 170);
        auto* root = new QVBoxLayout(&dialog);
        root->setContentsMargins(10, 7, 10, 7);
        root->setSpacing(5);
        auto* title = new QLabel(
            hasUpdate
                ? uiText(m_settings, "Доступна новая версия: %1", "New version is available: %1").arg(latestClean)
                : uiText(m_settings, "Установленна актуальная версия: %1", "Current version is installed: %1").arg(current),
            &dialog
        );
        title->setObjectName(QStringLiteral("sectionLabel"));
        QFont titleFont = title->font();
        titleFont.setPointSize(qMax(titleFont.pointSize() + 6, 18));
        titleFont.setBold(true);
        title->setFont(titleFont);
        title->setWordWrap(true);
        QPushButton* updateButton = nullptr;
        root->addWidget(title);
        QString body = object.value(QStringLiteral("body")).toString().trimmed();
        body.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        QStringList noteLines;
        for (QString line : body.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
            line = line.trimmed();
            while (line.startsWith(QLatin1Char('#')) || line.startsWith(QLatin1Char('-')) || line.startsWith(QLatin1Char('*'))) {
                line.remove(0, 1);
                line = line.trimmed();
            }
            if (!line.isEmpty()) {
                noteLines.append(line);
            }
            if (noteLines.size() >= 5) {
                break;
            }
        }
        QString notesText = noteLines.join(QLatin1Char('\n'));
        if (body.size() > notesText.size() + 80 || body.split(QLatin1Char('\n'), Qt::SkipEmptyParts).size() > noteLines.size()) {
            notesText += uiText(m_settings, "\n... ничего", "\n... nothing");
        }
        if (notesText.trimmed().isEmpty()) {
            notesText = uiText(m_settings, "Ничего", "Nothing");
        }
        auto* notes = new QLabel(notesText, &dialog);
        notes->setWordWrap(true);
        notes->setTextInteractionFlags(Qt::TextSelectableByMouse);
        notes->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        notes->setMaximumHeight(62);
        root->addWidget(notes, 1);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
        if (hasUpdate) {
            updateButton = new QPushButton(uiText(m_settings, "Обновить", "Update"), &dialog);
            buttons->addButton(updateButton, QDialogButtonBox::ActionRole);
        }
        if (auto* closeButton = buttons->button(QDialogButtonBox::Close)) {
            closeButton->setText(uiText(m_settings, "Закрыть", "Close"));
        }
        root->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        if (updateButton != nullptr) {
            connect(updateButton, &QPushButton::clicked, &dialog, [this, object, &dialog]() {
                QString assetUrl;
                const QJsonArray assets = object.value(QStringLiteral("assets")).toArray();
                for (const auto& value : assets) {
                    const QJsonObject asset = value.toObject();
                    const QString name = asset.value(QStringLiteral("name")).toString();
#ifdef Q_OS_WIN
                    const bool matchesPlatform = name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive);
#elif defined(Q_OS_MACOS)
                    const bool matchesPlatform = name.endsWith(QStringLiteral(".dmg"), Qt::CaseInsensitive);
#else
                    const bool matchesPlatform = name.endsWith(QStringLiteral(".sh"), Qt::CaseInsensitive);
#endif
                    if (matchesPlatform) {
                        assetUrl = asset.value(QStringLiteral("browser_download_url")).toString();
                        break;
                    }
                }
                if (assetUrl.isEmpty()) {
                    const QString url = object.value(QStringLiteral("html_url")).toString(QStringLiteral("https://github.com/DeziXsteroid/Universal_Network_Tools/releases/latest"));
                    QDesktopServices::openUrl(QUrl(url));
                    dialog.accept();
                    return;
                }
                auto* downloadReply = m_updateManager->get(QNetworkRequest(QUrl(assetUrl)));
                connect(downloadReply, &QNetworkReply::finished, this, [this, downloadReply, assetUrl]() {
                    const QByteArray data = downloadReply->readAll();
                    const bool ok = downloadReply->error() == QNetworkReply::NoError && !data.isEmpty();
                    downloadReply->deleteLater();
                    if (!ok) {
                        QMessageBox::warning(this, QStringLiteral("Help and Updates"), uiText(m_settings, "Не удалось скачать обновление.", "Could not download the update."));
                        return;
                    }
                    const QString fileName = QUrl(assetUrl).fileName();
                    const QString path = QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation)).filePath(fileName.isEmpty() ? QStringLiteral("NetworkToolsUpdate") : fileName);
                    QFile file(path);
                    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) || file.write(data) != data.size()) {
                        QMessageBox::warning(this, QStringLiteral("Help and Updates"), uiText(m_settings, "Не удалось сохранить обновление.", "Could not save the update."));
                        return;
                    }
                    file.close();
                    QProcess::startDetached(path, QStringList{});
                    qApp->quit();
                });
                dialog.accept();
            });
        }
        dialog.exec();
    });
}
