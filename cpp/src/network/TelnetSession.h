#pragma once

#include "core/Types.h"

#include <QObject>

class QTcpSocket;
class QTimer;

namespace nt {

class TelnetSession final : public QObject {
    Q_OBJECT

public:
    explicit TelnetSession(QObject* parent = nullptr);

    void open(const SessionProfile& profile);
    void close();
    void sendText(const QString& text);
    void sendBytes(const QByteArray& bytes);
    bool isConnected() const;

signals:
    void outputReady(const QString& text);
    void stateChanged(const QString& text);
    void connectedChanged(bool connected);

private:
    void handlePrompt(const QString& text);

    QTcpSocket* m_socket {nullptr};
    QTimer* m_connectTimer {nullptr};
    SessionProfile m_profile;
    bool m_usernameSent {false};
    bool m_passwordSent {false};
};

} // namespace nt
