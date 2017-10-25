#include "dialog.h"
#include "ui_dialog.h"
#include <QDebug>
#include <QUrl>
#include "QtWebSockets/qwebsocketserver.h"
#include "QtWebSockets/qwebsocket.h"
#include <QJsonObject>
#include <QJsonDocument>
#include <QFile>

#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>


// http://10.10.7.1/device
Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog),
    reply(Q_NULLPTR)/*,
    m_pWebSocketServer(QStringLiteral("Echo Server"),
                       QWebSocketServer::SecureMode, this),
    tcpServ(this)*/
{
    ui->setupUi(this);

    //int port = 9001;

    sslServ = new SslServer(this);
    if (sslServ->listen(QHostAddress::Any, PORT)) {
        qDebug() << "Echoserver listening on port" << PORT;
        connect(sslServ, SIGNAL(newConnection()),  this, SLOT(onNewSslConnection()));

        //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
    }

//    tcpServ = new QTcpServer(this);
//    if (tcpServ->listen(QHostAddress::Any, PORT)) {
//        qDebug() << "Echoserver listening on port" << PORT;
//        connect(tcpServ, SIGNAL(newConnection()),  this, SLOT(onNewConnection()));
//    //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
//    }

//    m_pWebSocketServer = new QWebSocketServer(QStringLiteral("Echo Server"),
//                                                QWebSocketServer::NonSecureMode, this);

//    QSslConfiguration sslConfiguration;
//    QFile certFile(QStringLiteral("ssl/localhost.cert"));
//    QFile keyFile(QStringLiteral("ssl/localhost.key"));
//    certFile.open(QIODevice::ReadOnly);
//    keyFile.open(QIODevice::ReadOnly);
//    QSslCertificate certificate(&certFile, QSsl::Pem);
//    QSslKey sslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
//    certFile.close();
//    keyFile.close();
//    //sslConfiguration.setPeerVerifyMode(QSslSocket::AutoVerifyPeer);
//    sslConfiguration.setLocalCertificate(certificate);
//    sslConfiguration.setPrivateKey(sslKey);
//    //sslConfiguration.setProtocol(QSsl::SslV2);
//    m_pWebSocketServer->setSslConfiguration(sslConfiguration);

//    if (m_pWebSocketServer->listen(QHostAddress::Any, PORT)) {
//        qDebug() << "Echoserver listening on port" << PORT;
//        connect(m_pWebSocketServer,  &QWebSocketServer::newConnection,
//                this,  &Dialog::handleWSNwConn);
//        connect(m_pWebSocketServer, SIGNAL(sslErrors(QList<QSslError>)),
//                this, SLOT(handleSSLError(QList<QSslError>)));
//        //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
//        connect(m_pWebSocketServer, SIGNAL(originAuthenticationRequired(QWebSocketCorsAuthenticator*)),
//                this, SLOT(handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator*)));
//        connect(m_pWebSocketServer, SIGNAL(peerVerifyError(QSslError)),
//                this, SLOT(handlePeerVerifyError(QSslError)));
//        connect(m_pWebSocketServer, SIGNAL(serverError(QWebSocketProtocol::CloseCode)),
//                this, SLOT(handleServerError(QWebSocketProtocol::CloseCode)));
//        connect(m_pWebSocketServer, SIGNAL(acceptError(QAbstractSocket::SocketError)),
//                this, SLOT(handleAcceptError()));

//    }


    connect(&qnam, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
            this, SLOT(handleSSLError(QNetworkReply*,QList<QSslError>)));

    connect(&qnam, &QNetworkAccessManager::authenticationRequired,
            this, &Dialog::slotAuthenticationRequired);
    connect(&qnam, SIGNAL(finished(QNetworkReply*)),
            this, SLOT(handleQNmFinished(QNetworkReply*)));

    timer.setInterval(500);
    timer.setSingleShot(false);
    connect(&timer, SIGNAL(timeout()),
            this, SLOT(handleTimer()));
    timer.start();

    //connect(&m_deb_client, &QWebSocket::connected, this, &Dialog::onWebSocketConnected);
    //connect(&m_deb_client, &QWebSocket::disconnected, this, &Dialog::onWebSocketClosed);
    //m_deb_client.open(QUrl(QString("http://192.168.0.101/device")));

}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::handleTimer()
{

//    if((reply == Q_NULLPTR) ||
//            ((reply != Q_NULLPTR) && (reply->isFinished()))){
//        qDebug("shot");
//        reply = qnam.get(QNetworkRequest(QUrl(QString("http://192.168.0.101/device"))));
//        connect(reply, &QNetworkReply::finished, this, &Dialog::handleHttpFinished);
//        connect(reply, &QIODevice::readyRead, this, &Dialog::handleHttpReadyRead);
//    }

}

void Dialog::slotAuthenticationRequired(QNetworkReply*,QAuthenticator *authenticator)
{
    qDebug() << "slotAuthenticationRequired";
}
void Dialog::handleHttpFinished()
{
    qDebug() << "handleHttpFinished";
    QByteArray ba = reply->readAll();
    qDebug() << ba;
    QJsonDocument doc(QJsonDocument::fromJson(ba));
    QJsonObject json = doc.object();
    qDebug() << json["deviceid"].toString().toLatin1();
    qDebug() << json["apikey"].toString().toLatin1();
    qDebug() << json["accept"].toString().toLatin1();
}

void Dialog::handleHttpReadyRead()
{
    qDebug() << "handleHttpReadyRead";
}

void Dialog::handleSSLError(QNetworkReply*,QList<QSslError>)
{
    qDebug() << "handleSSLError";
}

void Dialog::handleSSLError(QList<QSslError>)
{
    qDebug() << "handleSSLError" <<  sslSock->sslErrors();
}

void Dialog::onNewConnection()
{
    tcpSock = tcpServ->nextPendingConnection();
    //    //sslSock->ignoreSslErrors();
    connect(tcpSock, SIGNAL(readyRead()),
            this, SLOT(handleSocketReadyRead()));
    connect(tcpSock, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(handleSocketError(QAbstractSocket::SocketError)));
    connect(tcpSock, SIGNAL(disconnected()),
            this, SLOT(handleSocketDisconnected()));

    //serverStatusLabel->setText(tr("Accepted connection"));
    //tcpServer.close();
}

void Dialog::handleWSNwConn()
{
    qDebug() << "handleWSNwConn";
}

void Dialog::onNewSslConnection()
{
    qDebug() << "onNewSSLConnection";
    sslSock = (QSslSocket*)sslServ->nextPendingConnection();



    qDebug() << "isEncrypted" << sslSock->isEncrypted();
    connect(sslSock, SIGNAL(encrypted()),
            this, SLOT(handleEncrypted()));
    connect(sslSock, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(handleSSLError(QList<QSslError>)));
    connect(sslSock, SIGNAL(readyRead()),
            this, SLOT(handleSslSocketReadyRead()));
    connect(sslSock, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(handleSocketError(QAbstractSocket::SocketError)));
    connect(sslSock, SIGNAL(disconnected()),
            this, SLOT(handleSocketDisconnected()));

    //QSslConfiguration sslConfiguration;
    QFile certFile(QStringLiteral("ssl/server.crt"));
    QFile keyFile(QStringLiteral("ssl/priv.key"));

//    QFile certFile(QStringLiteral("ssl/localhost.cert"));
//    QFile keyFile(QStringLiteral("ssl/localhost.key"));
    qDebug() << certFile.open(QIODevice::ReadOnly);
    qDebug() << keyFile.open(QIODevice::ReadOnly);

    QSslCertificate certificate(&certFile, QSsl::Pem);
    QSslKey sslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
    certFile.close();
    keyFile.close();

    //sslConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);
    //sslConfiguration.setLocalCertificate(certificate);
    //sslConfiguration.setPrivateKey(sslKey);
    //sslConfiguration.setProtocol(QSsl::AnyProtocol);


    //sslSock->setSslConfiguration(sslConfiguration);
    sslSock->setPrivateKey(sslKey);
    sslSock->setLocalCertificate(certificate);

    sslSock->setProtocol(QSsl::AnyProtocol);
    //sslSock->setProtocol(QSsl::SslV2);

    sslSock->setLocalCertificate(certificate);
    sslSock->startServerEncryption();

//    tcpSock = tcpServ->nextPendingConnection();
//    //sslSock->ignoreSslErrors();
//    connect(tcpSock, SIGNAL(encrypted()),
//            this, SLOT(handleEncrypted()));
//    connect(tcpSock, SIGNAL(sslErrors(QList<QSslError>)),
//            this, SLOT(handleSSLError(QList<QSslError>)));
//    connect(tcpSock, SIGNAL(readyRead()),
//            this, SLOT(handleSocketReadyRead()));
//    connect(tcpSock, SIGNAL(error(QAbstractSocket::SocketError)),
//            this, SLOT(handleSocketError(QAbstractSocket::SocketError)));
//    connect(tcpSock, SIGNAL(disconnected()),
//            this, SLOT(handleSocketDisconnected()));

    //serverStatusLabel->setText(tr("Accepted connection"));
    //tcpServer.close();

}

void Dialog::handleSocketError(QAbstractSocket::SocketError err)
{
    qDebug() << "handleSocketError" << err << sslSock->sslErrors();
//    qDebug() << sslSock->sslErrors();
//    sslSock->ignoreSslErrors();


}

void Dialog::handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator *authenticator)
{
    qDebug() << "handleOriginAuthenticationRequired" ;
}

void Dialog::handleServerError(QWebSocketProtocol::CloseCode closeCode)
{
    qDebug() << "handleServerError" ;
}

void Dialog::handlePeerVerifyError(const QSslError &error)
{
    qDebug() << "handlePeerVerifyError";
}

void Dialog::handleSslSocketReadyRead()
{
    qDebug() << "handleSocketReadyRead" << sslSock->readAll();
    //qDebug() << "handleSocketReadyRead" ;

}

void Dialog::handleSocketReadyRead()
{
    QByteArray ba = tcpSock->readAll();
    QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
    QJsonObject rootObj = itemDoc.object();

    qDebug() << "handleSocketReadyRead" << ba;
    qDebug() << "handleSocketReadyRead" ;


//    QUrl url(QString("http://192.168.0.102/ap"));
//    QNetworkRequest request(url);

////    QByteArray jsonString = "{\n\"version\": 4,"
////                "\"ssid\": \"TL-WR842ND\","
////                "\"password\": \"kkkknnnn\","
////                "\"serverName\": \"192.168.0.105\","
////                "\"port\": 80\n}";

//    //QByteArray postDataSize = QByteArray::number(jsonString.size());


//    QJsonObject json;
//    json.insert("error", 0);
//    json.insert("deviceid", "TL-WR842ND");
//    json.insert("apikey", "111111111-1111-1111-1111-111111111111");

//    QByteArray data = QJsonDocument(json).toJson().data();
//    QByteArray postDataSize = QByteArray::number(data.size());
//    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
//    request.setHeader(QNetworkRequest::ContentLengthHeader, postDataSize);


//    tcpSock->write();
//    reply = qnam.post(request, data);

//    connect(reply, SIGNAL(finished()), this, SLOT(handleHttpFinished()));
//    connect(reply, SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(handleReplyError(QNetworkReply::NetworkError)));
//    connect(reply, &QIODevice::readyRead, this, &Dialog::handleHttpReadyRead);


}

void Dialog::handleSocketDisconnected()
{
    qDebug() << "handleSocketDisconnected";
}

void Dialog::handleEncrypted()
{
    qDebug() << "handleEncrypted";
}

void Dialog::onWebSocketConnected()
{
    qDebug() << "onWebSocketConnected";

}

void Dialog::onWebSocketClosed()
{
    qDebug() << "onWebSocketClosed";

}
void Dialog::handleReplyError(QNetworkReply::NetworkError err)
{
    qDebug() << "replyError" << err;
}

void Dialog::handleQNmFinished(QNetworkReply* r)
{
    qDebug() << "handleQNmFinished";
}

void Dialog::on_pushButtonSendReg_clicked()
{
    QUrl url(QString("http://10.10.7.1/ap"));
    QNetworkRequest request(url);

//    QByteArray jsonString = "{\n\"version\": 4,"
//                "\"ssid\": \"TL-WR842ND\","
//                "\"password\": \"kkkknnnn\","
//                "\"serverName\": \"192.168.0.105\","
//                "\"port\": 80\n}";

    //QByteArray postDataSize = QByteArray::number(jsonString.size());

    QJsonObject json;
    json.insert("version", 4);
    json.insert("ssid", "TL-WR842ND");
    json.insert("password", "kkkknnnn");
    json.insert("serverName", "192.168.0.105");
    json.insert("port", PORT);

    QByteArray data = QJsonDocument(json).toJson().data();

    QByteArray postDataSize = QByteArray::number(data.size());


    //request.setRawHeader("Content-Type", "application/json");
    //request.setRawHeader("Content-Length", postDataSize);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setHeader(QNetworkRequest::ContentLengthHeader, postDataSize);


    reply = qnam.post(request, data);

    connect(reply, SIGNAL(finished()), this, SLOT(handleHttpFinished()));
    connect(reply, SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(handleReplyError(QNetworkReply::NetworkError)));
    connect(reply, &QIODevice::readyRead, this, &Dialog::handleHttpReadyRead);


    //qDebug() << "[POST]" << request.request(false).url().toString()
}

void Dialog::on_pushButtonGetReq_clicked()
{
    QNetworkRequest netReq(QString("http://10.10.7.1/device"));
    reply = qnam.get(netReq);

    connect(reply, &QNetworkReply::finished, this, &Dialog::handleHttpFinished);
    connect(reply, SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(handleReplyError(QNetworkReply::NetworkError)));
    connect(reply, &QIODevice::readyRead, this, &Dialog::handleHttpReadyRead);
}


void Dialog::handleAcceptError()
{
    qDebug() << "handleAcceptError";

}
