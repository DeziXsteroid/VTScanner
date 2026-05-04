#include "network/SshProcessSession.h"

#include "core/TerminalSanitizer.h"

#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>

namespace nt {

SshProcessSession::SshProcessSession(QObject* parent)
    : QObject(parent)
    , m_process(new QProcess(this)) {
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
        handleProcessText(TerminalSanitizer::sanitizeTerminal(m_process->readAllStandardOutput()));
    });
    connect(m_process, &QProcess::started, this, [this]() {
        m_connected = false;
        m_authRejected = false;
        emit stateChanged(QStringLiteral("Подключение SSH..."));
        emit connectedChanged(false);
    });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        m_connected = false;
        emit stateChanged(m_process->errorString());
        emit connectedChanged(false);
    });
    connect(m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this, [this](int exitCode, QProcess::ExitStatus) {
        const bool wasConnected = m_connected;
        m_connected = false;
        emit connectedChanged(false);
        if (m_authRejected) {
            emit stateChanged(QStringLiteral("Доступ отклонен"));
            return;
        }
        if (wasConnected || exitCode == 0) {
            emit stateChanged(QStringLiteral("Отключено"));
            return;
        }
        emit stateChanged(QStringLiteral("SSH завершился"));
    });
}

QStringList SshProcessSession::buildCommand(const SessionProfile& profile, QString* program) const {
    const auto tclQuote = [](QString value) {
        value.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        value.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        value.replace(QStringLiteral("$"), QStringLiteral("\\$"));
        value.replace(QStringLiteral("["), QStringLiteral("\\["));
        value.replace(QStringLiteral("]"), QStringLiteral("\\]"));
        return QStringLiteral("\"%1\"").arg(value);
    };
    const QString hostTarget = profile.username.trimmed().isEmpty()
        ? profile.host
        : QStringLiteral("%1@%2").arg(profile.username, profile.host);

#ifdef Q_OS_WIN
    if (!profile.password.isEmpty()) {
        const QString plink = QStandardPaths::findExecutable(QStringLiteral("plink"));
        if (!plink.isEmpty()) {
            *program = plink;
            return {
                QStringLiteral("-ssh"),
                QStringLiteral("-P"), QString::number(profile.port),
                QStringLiteral("-pw"), profile.password,
                hostTarget,
            };
        }
    }
#else
    if (!profile.password.isEmpty()) {
        const QString sshpass = QStandardPaths::findExecutable(QStringLiteral("sshpass"));
        if (!sshpass.isEmpty()) {
            *program = sshpass;
            return {
                QStringLiteral("-e"),
                QStringLiteral("ssh"),
                QStringLiteral("-tt"),
                QStringLiteral("-o"), QStringLiteral("PreferredAuthentications=password,keyboard-interactive"),
                QStringLiteral("-o"), QStringLiteral("PubkeyAuthentication=no"),
                QStringLiteral("-o"), QStringLiteral("KbdInteractiveAuthentication=yes"),
                QStringLiteral("-o"), QStringLiteral("NumberOfPasswordPrompts=1"),
                QStringLiteral("-o"), QStringLiteral("LogLevel=ERROR"),
                QStringLiteral("-o"), QStringLiteral("StrictHostKeyChecking=accept-new"),
                QStringLiteral("-p"), QString::number(profile.port),
                hostTarget,
            };
        }
        const QString expect = QStandardPaths::findExecutable(QStringLiteral("expect"));
        if (!expect.isEmpty()) {
            *program = expect;
            const QString expectScript = QStringLiteral(
                "set timeout -1\n"
                "match_max 100000\n"
                "set host %1\n"
                "set port %2\n"
                "set user %3\n"
                "set password $env(NETWORKTOOLS_SSH_PASSWORD)\n"
                "if {$user eq \"\"} {\n"
                "    set target $host\n"
                "} else {\n"
                "    set target \"$user@$host\"\n"
                "}\n"
                "log_user 0\n"
                "spawn -noecho ssh -tt -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=yes -o NumberOfPasswordPrompts=1 -p $port $target\n"
                "expect {\n"
                "    -re {(?i)continue connecting.*} { send -- \"yes\\r\"; exp_continue }\n"
                "    -re {(?i)(password|passphrase):\\s*$} { send -- \"$password\\r\" }\n"
                "    timeout { puts \"SSH timeout\"; exit 124 }\n"
                "    eof { catch wait result; exit [lindex $result 3] }\n"
                "}\n"
                "log_user 1\n"
                "interact\n"
            ).arg(tclQuote(profile.host), tclQuote(QString::number(profile.port)), tclQuote(profile.username));
            return {
                QStringLiteral("-c"),
                expectScript,
            };
        }
    }
#endif

    *program = QStandardPaths::findExecutable(QStringLiteral("ssh"));
    return {
        QStringLiteral("-tt"),
        QStringLiteral("-o"), QStringLiteral("LogLevel=ERROR"),
        QStringLiteral("-o"), QStringLiteral("StrictHostKeyChecking=accept-new"),
        QStringLiteral("-p"), QString::number(profile.port),
        hostTarget,
    };
}

void SshProcessSession::open(const SessionProfile& profile) {
    close();
    m_profile = profile;
    m_authRejected = false;
    QString program;
    const auto arguments = buildCommand(profile, &program);
    if (program.isEmpty()) {
        emit stateChanged(QStringLiteral("SSH-клиент не найден. Установите OpenSSH, sshpass или plink."));
        emit connectedChanged(false);
        return;
    }
    auto environment = QProcessEnvironment::systemEnvironment();
    const QString programName = QFileInfo(program).fileName();
    if (programName == QStringLiteral("expect") && !profile.password.isEmpty()) {
        environment.insert(QStringLiteral("NETWORKTOOLS_SSH_PASSWORD"), profile.password);
        environment.remove(QStringLiteral("SSHPASS"));
    } else if (programName == QStringLiteral("sshpass") && !profile.password.isEmpty()) {
        environment.insert(QStringLiteral("SSHPASS"), profile.password);
        environment.remove(QStringLiteral("NETWORKTOOLS_SSH_PASSWORD"));
    } else {
        environment.remove(QStringLiteral("NETWORKTOOLS_SSH_PASSWORD"));
        environment.remove(QStringLiteral("SSHPASS"));
    }
    m_process->setProcessEnvironment(environment);
    m_process->start(program, arguments);
}

void SshProcessSession::close() {
    if (m_process->state() == QProcess::NotRunning) {
        m_connected = false;
        return;
    }
    m_process->terminate();
    if (!m_process->waitForFinished(1200)) {
        m_process->kill();
        m_process->waitForFinished(800);
    }
    m_connected = false;
}

void SshProcessSession::sendText(const QString& text) {
    sendBytes(text.toUtf8() + QByteArrayLiteral("\n"));
}

void SshProcessSession::sendBytes(const QByteArray& bytes) {
    if (m_process->state() != QProcess::Running) {
        emit stateChanged(QStringLiteral("SSH не подключен"));
        return;
    }
    m_process->write(bytes);
}

bool SshProcessSession::isConnected() const {
    return m_connected && m_process->state() == QProcess::Running;
}

void SshProcessSession::handleProcessText(const QString& text) {
    if (text.isEmpty()) {
        return;
    }
    const QString lower = text.toLower();
    if (lower.contains(QStringLiteral("permission denied"))
        || lower.contains(QStringLiteral("access denied"))
        || lower.contains(QStringLiteral("authentication failed"))) {
        m_authRejected = true;
        emit stateChanged(QStringLiteral("Доступ отклонен"));
    } else if (!m_connected) {
        m_connected = true;
        emit stateChanged(QStringLiteral("SSH %1:%2").arg(m_profile.host).arg(m_profile.port));
        emit connectedChanged(true);
    }
    emit outputReady(text);
}

} // namespace nt
