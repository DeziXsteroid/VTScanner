#pragma once

#include <QObject>

class QTcpSocket;
class QTimer;

namespace nt {

class TcpClientSession final : public QObject {
    Q_OBJECT

public:
    explicit TcpClientSession(QObject* parent = nullptr);

    bool open(const QString& host, quint16 port, quint16 localPort, bool noDelay, bool keepAlive, QString* errorText);
    void close();
    void sendBytes(const QByteArray& bytes);
    bool isConnected() const;

signals:
    void dataReceived(const QByteArray& bytes);
    void stateChanged(const QString& text);
    void connectedChanged(bool connected);

private:
    QTcpSocket* m_socket {nullptr};
    QTimer* m_connectTimer {nullptr};
    QString m_host;
    quint16 m_port {0};
    quint16 m_localPort {0};
    bool m_noDelay {false};
    bool m_keepAlive {false};
};

} // namespace nt
