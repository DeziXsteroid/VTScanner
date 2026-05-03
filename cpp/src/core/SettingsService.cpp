#include "core/SettingsService.h"

#include "core/AppPaths.h"

#include <QFile>
#include <QJsonDocument>

namespace nt {

namespace {

QJsonObject deepMerge(const QJsonObject& base, const QJsonObject& overlay) {
    QJsonObject result = base;
    for (auto it = overlay.begin(); it != overlay.end(); ++it) {
        if (it->isObject() && result.value(it.key()).isObject()) {
            result.insert(it.key(), deepMerge(result.value(it.key()).toObject(), it->toObject()));
        } else {
            result.insert(it.key(), *it);
        }
    }
    return result;
}

} // namespace

SettingsService::SettingsService(QObject* parent)
    : QObject(parent) {
    AppPaths::ensureRuntimeTree();
    m_config = defaultConfig();
}

bool SettingsService::load() {
    AppPaths::ensureRuntimeTree();
    QFile file(AppPaths::settingsPath());
    if (!file.exists()) {
        m_config = defaultConfig();
        return save();
    }
    if (!file.open(QIODevice::ReadOnly)) {
        m_config = defaultConfig();
        return false;
    }

    const auto doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    if (!doc.isObject()) {
        m_config = defaultConfig();
        return false;
    }

    m_config = deepMerge(defaultConfig(), doc.object());
    return true;
}

bool SettingsService::save() const {
    AppPaths::ensureRuntimeTree();
    QFile file(AppPaths::settingsPath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    file.write(QJsonDocument(m_config).toJson(QJsonDocument::Indented));
    return true;
}

QJsonObject SettingsService::config() const {
    return m_config;
}

QJsonObject SettingsService::section(const QString& key) const {
    return m_config.value(key).toObject();
}

void SettingsService::setSection(const QString& key, const QJsonObject& value) {
    m_config.insert(key, value);
    emit changed();
}

QJsonValue SettingsService::value(const QString& key, const QJsonValue& defaultValue) const {
    return m_config.value(key).isUndefined() ? defaultValue : m_config.value(key);
}

void SettingsService::setValue(const QString& key, const QJsonValue& value) {
    m_config.insert(key, value);
    emit changed();
}

QSize SettingsService::initialWindowSize() const {
    const auto object = section(QStringLiteral("window"));
    const int width = qBound(840, object.value(QStringLiteral("width")).toInt(874), 920);
    const int height = qBound(440, object.value(QStringLiteral("height")).toInt(472), 522);
    return QSize(width, height);
}

int SettingsService::scanWorkers() const {
    return qBound(8, value(QStringLiteral("scan_workers"), 96).toInt(96), 96);
}

QString SettingsService::theme() const {
    const QString current = value(QStringLiteral("theme"), QStringLiteral("dark")).toString(QStringLiteral("dark")).trimmed().toLower();
    return current == QStringLiteral("light") ? QStringLiteral("light") : QStringLiteral("dark");
}

QString SettingsService::language() const {
    const QString current = value(QStringLiteral("language"), QStringLiteral("ru")).toString(QStringLiteral("ru")).trimmed().toLower();
    return current == QStringLiteral("en") ? QStringLiteral("en") : QStringLiteral("ru");
}

QList<SessionProfile> SettingsService::sessionProfiles(const QString& key, quint16 defaultPort) const {
    const auto object = section(key);
    return sessionProfilesFromJson(object.value(QStringLiteral("profiles")).toArray(), defaultPort);
}

void SettingsService::storeSessionProfiles(const QString& key, const QList<SessionProfile>& profiles, const SessionProfile& current) {
    auto object = section(key);
    object.insert(QStringLiteral("host"), current.host);
    object.insert(QStringLiteral("port"), static_cast<int>(current.port));
    object.insert(QStringLiteral("username"), current.username);
    object.insert(QStringLiteral("last_profile"), current.name);
    object.insert(QStringLiteral("profiles"), sessionProfilesToJson(profiles));
    setSection(key, object);
}

QJsonObject SettingsService::defaultConfig() {
    return QJsonObject{
        {QStringLiteral("theme"), QStringLiteral("dark")},
        {QStringLiteral("language"), QStringLiteral("ru")},
        {QStringLiteral("terminal_text_color"), QStringLiteral("mint")},
        {QStringLiteral("ui_scale"), 92},
        {QStringLiteral("scan_workers"), 96},
        {QStringLiteral("auto_scan_enabled"), false},
        {QStringLiteral("auto_scan_interval_sec"), 30},
        {QStringLiteral("scan_on_startup"), true},
        {QStringLiteral("vendor_auto_update"), true},
        {QStringLiteral("http_history"), QJsonArray{}},
        {QStringLiteral("window"), QJsonObject{
            {QStringLiteral("width"), 874},
            {QStringLiteral("height"), 472},
        }},
        {QStringLiteral("snmp"), QJsonObject{
            {QStringLiteral("host"), QString()},
            {QStringLiteral("port"), 161},
            {QStringLiteral("version"), QStringLiteral("2c")},
            {QStringLiteral("read_community"), QString()},
            {QStringLiteral("write_community"), QString()},
            {QStringLiteral("v3_user"), QString()},
            {QStringLiteral("v3_security_level"), QStringLiteral("noAuthNoPriv")},
            {QStringLiteral("v3_auth_protocol"), QStringLiteral("SHA")},
            {QStringLiteral("v3_auth_password"), QString()},
            {QStringLiteral("v3_privacy_protocol"), QStringLiteral("AES")},
            {QStringLiteral("v3_privacy_password"), QString()},
            {QStringLiteral("base_oid"), QStringLiteral(".1")},
            {QStringLiteral("profiles"), QJsonArray()},
        }},
        {QStringLiteral("ssh"), QJsonObject{
            {QStringLiteral("host"), QStringLiteral("127.0.0.1")},
            {QStringLiteral("port"), 22},
            {QStringLiteral("username"), QString()},
            {QStringLiteral("last_profile"), QString()},
            {QStringLiteral("profiles"), QJsonArray()},
        }},
        {QStringLiteral("telnet"), QJsonObject{
            {QStringLiteral("host"), QStringLiteral("127.0.0.1")},
            {QStringLiteral("port"), 23},
            {QStringLiteral("username"), QString()},
            {QStringLiteral("last_profile"), QString()},
            {QStringLiteral("profiles"), QJsonArray()},
        }},
        {QStringLiteral("serial"), QJsonObject{
            {QStringLiteral("baud"), QStringLiteral("9600")},
            {QStringLiteral("data_bits"), QStringLiteral("8")},
            {QStringLiteral("parity"), QStringLiteral("Нет")},
            {QStringLiteral("stop_bits"), QStringLiteral("1")},
            {QStringLiteral("flow_control"), QStringLiteral("Нет")},
            {QStringLiteral("eol"), QStringLiteral("Нет")},
            {QStringLiteral("draft"), QString()},
            {QStringLiteral("quick_commands"), QJsonArray{QString(), QString(), QString()}},
        }},
        {QStringLiteral("tcp"), QJsonObject{
            {QStringLiteral("host"), QStringLiteral("127.0.0.1")},
            {QStringLiteral("port"), 23},
            {QStringLiteral("local_port"), 0},
            {QStringLiteral("no_delay"), true},
            {QStringLiteral("keep_alive"), false},
            {QStringLiteral("eol"), QStringLiteral("Нет")},
            {QStringLiteral("draft"), QString()},
            {QStringLiteral("quick_commands"), QJsonArray{QString(), QString(), QString()}},
        }},
        {QStringLiteral("udp"), QJsonObject{
            {QStringLiteral("host"), QStringLiteral("127.0.0.1")},
            {QStringLiteral("remote_port"), 52381},
            {QStringLiteral("local_port"), 0},
            {QStringLiteral("reuse_address"), true},
            {QStringLiteral("eol"), QStringLiteral("Нет")},
            {QStringLiteral("draft"), QString()},
            {QStringLiteral("quick_commands"), QJsonArray{QString(), QString(), QString()}},
        }},
    };
}

} // namespace nt
