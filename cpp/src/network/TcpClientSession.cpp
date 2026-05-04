#include "network/TcpClientSession.h"

#include <QHostAddress>
#include <QTcpSocket>
#include <QTimer>

namespace nt {

TcpClientSession::TcpClientSession(QObject* parent)
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
        emit stateChanged(QStringLiteral("TCP timeout"));
        emit connectedChanged(false);
    });
    connect(m_socket, &QTcpSocket::connected, this, [this]() {
        m_connectTimer->stop();
        m_socket->setSocketOption(QAbstractSocket::LowDelayOption, m_noDelay ? 1 : 0);
        m_socket->setSocketOption(QAbstractSocket::KeepAliveOption, m_keepAlive ? 1 : 0);
        emit stateChanged(QStringLiteral("TCP %1:%2").arg(m_host).arg(m_port));
        emit connectedChanged(true);
    });
    connect(m_socket, &QTcpSocket::readyRead, this, [this]() {
        emit dataReceived(m_socket->readAll());
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

bool TcpClientSession::open(const QString& host, quint16 port, quint16 localPort, bool noDelay, bool keepAlive, QString* errorText) {
    m_host = host;
    m_port = port;
    m_localPort = localPort;
    m_noDelay = noDelay;
    m_keepAlive = keepAlive;
    m_socket->abort();
    if (localPort > 0 && !m_socket->bind(QHostAddress::AnyIPv4, localPort)) {
        if (errorText != nullptr) {
            *errorText = m_socket->errorString();
        }
        emit stateChanged(m_socket->errorString());
        emit connectedChanged(false);
        return false;
    }
    m_socket->connectToHost(host, port);
    m_connectTimer->start();
    return true;
}

void TcpClientSession::close() {
    m_connectTimer->stop();
    m_socket->disconnectFromHost();
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->abort();
    }
}

void TcpClientSession::sendBytes(const QByteArray& bytes) {
    if (m_socket->state() != QAbstractSocket::ConnectedState) {
        emit stateChanged(QStringLiteral("TCP не подключен"));
        return;
    }
    m_socket->write(bytes);
}

bool TcpClientSession::isConnected() const {
    return m_socket->state() == QAbstractSocket::ConnectedState;
}

} // namespace nt
