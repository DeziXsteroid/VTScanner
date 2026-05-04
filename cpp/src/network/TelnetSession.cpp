#include "network/TelnetSession.h"

#include "core/TerminalSanitizer.h"

#include <QTcpSocket>
#include <QTimer>

namespace nt {

TelnetSession::TelnetSession(QObject* parent)
    : QObject(parent)
    , m_socket(new QTcpSocket(this))
    , m_connectTimer(new QTimer(this)) {
    m_connectTimer->setSingleShot(true);
    m_connectTimer->setInterval(8000);
    connect(m_connectTimer, &QTimer::timeout, this, [this]() {
        if (m_socket->state() == QAbstractSocket::ConnectedState
            || m_socket->state() == QAbstractSocket::UnconnectedState) {
            return;
        }
        m_socket->abort();
        emit stateChanged(QStringLiteral("Telnet timeout"));
        emit connectedChanged(false);
    });
    connect(m_socket, &QTcpSocket::connected, this, [this]() {
        m_connectTimer->stop();
        emit stateChanged(QStringLiteral("Telnet %1:%2").arg(m_profile.host).arg(m_profile.port));
        emit connectedChanged(true);
    });
    connect(m_socket, &QTcpSocket::readyRead, this, [this]() {
        const QString text = TerminalSanitizer::sanitizeTerminal(m_socket->readAll());
        handlePrompt(text);
        emit outputReady(text);
    });
    connect(m_socket, &QTcpSocket::disconnected, this, [this]() {
        m_connectTimer->stop();
        emit stateChanged(QStringLiteral("Отключено"));
        emit connectedChanged(false);
    });
    connect(m_socket, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        m_connectTimer->stop();
        emit stateChanged(m_socket->errorString());
        emit connectedChanged(false);
    });
}

void TelnetSession::open(const SessionProfile& profile) {
    m_profile = profile;
    m_usernameSent = false;
    m_passwordSent = false;
    m_socket->abort();
    m_socket->connectToHost(profile.host, profile.port);
    m_connectTimer->start();
}

void TelnetSession::close() {
    m_connectTimer->stop();
    m_socket->disconnectFromHost();
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->abort();
    }
}

void TelnetSession::sendText(const QString& text) {
    sendBytes(text.toUtf8() + QByteArrayLiteral("\r\n"));
}

void TelnetSession::sendBytes(const QByteArray& bytes) {
    if (m_socket->state() != QAbstractSocket::ConnectedState) {
        emit stateChanged(QStringLiteral("Telnet не подключен"));
        return;
    }
    m_socket->write(bytes);
}

bool TelnetSession::isConnected() const {
    return m_socket->state() == QAbstractSocket::ConnectedState;
}

void TelnetSession::handlePrompt(const QString& text) {
    const QString lower = text.toLower();
    if (!m_usernameSent
        && !m_profile.username.isEmpty()
        && (lower.contains(QStringLiteral("login:")) || lower.contains(QStringLiteral("username:")))) {
        sendBytes(m_profile.username.toUtf8() + QByteArrayLiteral("\r\n"));
        m_usernameSent = true;
    }
    if (!m_passwordSent
        && !m_profile.password.isEmpty()
        && lower.contains(QStringLiteral("password:"))) {
        sendBytes(m_profile.password.toUtf8() + QByteArrayLiteral("\r\n"));
        m_passwordSent = true;
    }
    if (lower.contains(QStringLiteral("login incorrect"))
        || lower.contains(QStringLiteral("authentication failed"))
        || lower.contains(QStringLiteral("access denied"))) {
        emit stateChanged(QStringLiteral("Доступ отклонен"));
    }
}

} // namespace nt
