#pragma once

#include "core/Types.h"

#include <QJsonObject>
#include <QObject>
#include <QSize>

namespace nt {

class SettingsService final : public QObject {
    Q_OBJECT

public:
    explicit SettingsService(QObject* parent = nullptr);

    bool load();
    bool save() const;

    QJsonObject config() const;
    QJsonObject section(const QString& key) const;
    void setSection(const QString& key, const QJsonObject& value);
    QJsonValue value(const QString& key, const QJsonValue& defaultValue = {}) const;
    void setValue(const QString& key, const QJsonValue& value);

    QSize initialWindowSize() const;
    int scanWorkers() const;
    QString scanProfile() const;
    QString theme() const;
    QString language() const;

    QList<SessionProfile> sessionProfiles(const QString& key, quint16 defaultPort) const;
    void storeSessionProfiles(const QString& key, const QList<SessionProfile>& profiles, const SessionProfile& current);

    static QJsonObject defaultConfig();

signals:
    void changed();

private:
    QJsonObject m_config;
};

} // namespace nt
