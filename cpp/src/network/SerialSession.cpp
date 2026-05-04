#include "network/SerialSession.h"

#include <QSerialPort>

namespace nt {

namespace {

QSerialPort::DataBits resolveDataBits(int bits) {
    return bits == 7 ? QSerialPort::Data7 : QSerialPort::Data8;
}

QSerialPort::Parity resolveParity(const QString& parityName) {
    const QString name = parityName.trimmed().toLower();
    if (name == QStringLiteral("even") || name == QStringLiteral("чет")) {
        return QSerialPort::EvenParity;
    }
    if (name == QStringLiteral("odd") || name == QStringLiteral("нечет")) {
        return QSerialPort::OddParity;
    }
    return QSerialPort::NoParity;
}

QSerialPort::StopBits resolveStopBits(const QString& stopBitsName) {
    const QString name = stopBitsName.trimmed();
    if (name == QStringLiteral("1.5")) {
        return QSerialPort::OneAndHalfStop;
    }
    if (name == QStringLiteral("2")) {
        return QSerialPort::TwoStop;
    }
    return QSerialPort::OneStop;
}

QSerialPort::FlowControl resolveFlowControl(const QString& flowControlName) {
    const QString name = flowControlName.trimmed().toLower();
    if (name == QStringLiteral("hardware") || name == QStringLiteral("rts/cts")) {
        return QSerialPort::HardwareControl;
    }
    if (name == QStringLiteral("software") || name == QStringLiteral("xon/xoff")) {
        return QSerialPort::SoftwareControl;
    }
    return QSerialPort::NoFlowControl;
}

} // namespace

SerialSession::SerialSession(QObject* parent)
    : QObject(parent)
    , m_port(new QSerialPort(this)) {
    connect(m_port, &QSerialPort::readyRead, this, [this]() {
        emit dataReceived(m_port->readAll());
    });
    connect(m_port, &QSerialPort::errorOccurred, this, [this](QSerialPort::SerialPortError error) {
        if (error == QSerialPort::NoError) {
            return;
        }
        emit stateChanged(m_port->errorString());
    });
}

bool SerialSession::open(const QString& portName, qint32 baudRate, int dataBits, const QString& parityName, const QString& stopBitsName, const QString& flowControlName, QString* errorText) {
    close();
    m_port->setPortName(portName);
    m_port->setBaudRate(baudRate);
    m_port->setDataBits(resolveDataBits(dataBits));
    m_port->setParity(resolveParity(parityName));
    m_port->setStopBits(resolveStopBits(stopBitsName));
    m_port->setFlowControl(resolveFlowControl(flowControlName));
    if (!m_port->open(QIODevice::ReadWrite)) {
        if (errorText != nullptr) {
            *errorText = m_port->errorString();
        }
        emit stateChanged(m_port->errorString());
        emit connectedChanged(false);
        return false;
    }
    emit stateChanged(QStringLiteral("Serial %1 @ %2").arg(portName).arg(baudRate));
    emit connectedChanged(true);
    return true;
}

void SerialSession::close() {
    if (m_port->isOpen()) {
        m_port->close();
        emit stateChanged(QStringLiteral("Отключено"));
        emit connectedChanged(false);
    }
}

void SerialSession::sendBytes(const QByteArray& bytes, QString* errorText) {
    if (!m_port->isOpen()) {
        if (errorText != nullptr) {
            *errorText = QStringLiteral("Serial не подключен");
        }
        emit stateChanged(QStringLiteral("Serial не подключен"));
        return;
    }
    qint64 totalWritten = 0;
    while (totalWritten < bytes.size()) {
        const auto written = m_port->write(bytes.constData() + totalWritten, bytes.size() - totalWritten);
        if (written < 0) {
            if (errorText != nullptr) {
                *errorText = m_port->errorString();
            }
            emit stateChanged(m_port->errorString());
            return;
        }
        if (written == 0 && !m_port->waitForBytesWritten(120)) {
            const QString text = QStringLiteral("Serial записал не все байты");
            if (errorText != nullptr) {
                *errorText = text;
            }
            emit stateChanged(text);
            return;
        }
        totalWritten += written;
    }
    m_port->flush();
}

bool SerialSession::isOpen() const {
    return m_port->isOpen();
}

} // namespace nt
