#include "network/HttpRequestService.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

namespace nt {

HttpRequestService::HttpRequestService(QObject* parent)
    : QObject(parent)
    , m_manager(new QNetworkAccessManager(this)) {
}

void HttpRequestService::send(const HttpRequestSpec& spec) {
    QString rawUrl = spec.url.trimmed();
    if (!rawUrl.contains(QRegularExpression(QStringLiteral("^[a-zA-Z][a-zA-Z0-9+.-]*://")))) {
        rawUrl.prepend(QStringLiteral("http://"));
    }
    QUrl url = QUrl::fromUserInput(rawUrl);
    QUrlQuery query(url);
    for (auto it = spec.params.begin(); it != spec.params.end(); ++it) {
        query.addQueryItem(it.key(), it->toVariant().toString());
    }
    url.setQuery(query);

    QNetworkRequest request(url);
    request.setTransferTimeout(qBound(1, spec.timeoutSec, 3600) * 1000);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    bool hasUserAgent = false;
    for (auto it = spec.headers.begin(); it != spec.headers.end(); ++it) {
        if (it.key().compare(QStringLiteral("User-Agent"), Qt::CaseInsensitive) == 0) {
            hasUserAgent = true;
        }
        request.setRawHeader(it.key().toUtf8(), it->toVariant().toString().toUtf8());
    }
    if (!hasUserAgent) {
    request.setRawHeader("User-Agent", QByteArrayLiteral("NetworkToolsQt/1.1"));
    }

    if (!spec.username.isEmpty()) {
        const QByteArray token = QStringLiteral("%1:%2").arg(spec.username, spec.password).toUtf8().toBase64();
        request.setRawHeader("Authorization", "Basic " + token);
    }

    const QByteArray method = spec.method.trimmed().isEmpty() ? QByteArrayLiteral("GET") : spec.method.toUpper().toUtf8();
    QNetworkReply* reply = m_manager->sendCustomRequest(request, method, spec.body);
    connect(reply, &QNetworkReply::finished, this, [this, reply, url, method]() {
        HttpResponse response;
        response.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        response.body = reply->readAll();
        response.method = QString::fromUtf8(method);
        response.url = url.toString();
        response.reasonPhrase = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
        if (reply->error() != QNetworkReply::NoError) {
            response.errorText = reply->errorString();
        }
        const auto headers = reply->rawHeaderPairs();
        for (const auto& header : headers) {
            response.headers.insert(QString::fromUtf8(header.first), QString::fromUtf8(header.second));
        }
        emit finished(response);
        reply->deleteLater();
    });
}

} // namespace nt
