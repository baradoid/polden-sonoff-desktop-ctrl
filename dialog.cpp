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
    m_pWebSocketServer(Q_NULLPTR),
    tcpServ(this)*/
{
    ui->setupUi(this);

    //int port = 9001;
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
    sslConfiguration.setLocalCertificate(certificate);
    sslConfiguration.setPrivateKey(sslKey);
    sslConfiguration.setProtocol(QSsl::AnyProtocol);


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

//    m_pWebSocketServer = new QWebSocketServer(QStringLiteral("SSL Echo Server"),
//                                                QWebSocketServer::SecureMode, this);


////    //sslConfiguration.setProtocol(QSsl::SslV2);
//    m_pWebSocketServer->setSslConfiguration(sslConfiguration);
//    m_pWebSocketServer->set

//    connect(m_pWebSocketServer,  SIGNAL(newConnection()),
//            this,  SLOT(handleWSNwConn()));
//    connect(m_pWebSocketServer, SIGNAL(sslErrors(QList<QSslError>)),
//            this, SLOT(handleSSLError(QList<QSslError>)));
//    //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
//    connect(m_pWebSocketServer, SIGNAL(originAuthenticationRequired(QWebSocketCorsAuthenticator*)),
//            this, SLOT(handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator*)));
//    connect(m_pWebSocketServer, SIGNAL(peerVerifyError(QSslError)),
//            this, SLOT(handlePeerVerifyError(QSslError)));
//    connect(m_pWebSocketServer, SIGNAL(serverError(QWebSocketProtocol::CloseCode)),
//            this, SLOT(handleServerError(QWebSocketProtocol::CloseCode)));
//    connect(m_pWebSocketServer, SIGNAL(acceptError(QAbstractSocket::SocketError)),
//            this, SLOT(handleAcceptError(QAbstractSocket::SocketError)));

//    if (m_pWebSocketServer->listen(QHostAddress::Any, PORT)) {
//        qDebug() << "Echoserver listening on port" << PORT;
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
    //QWebSocket *ws = m_pWebSocketServer->nextPendingConnection();

    qDebug() << "handleWSNwConn";

}

void Dialog::onNewSslConnection()
{
    qDebug() << "onNewSSLConnection";
    sslSock = (QSslSocket*)sslServ->nextPendingConnection();

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

    sslSock->setSslConfiguration(sslConfiguration);
    sslSock->startServerEncryption();
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
    QByteArray ba = sslSock->readAll();

    //qDebug() << "handleSocketReadyRead" ;
    QString msg(ba);
    if(msg.startsWith("POST /dispatch/device HTTP/1.1\r\n")){
        qDebug() << "dispatch/device";
        //qDebug() << "handleSocketReadyRead" << ba;
        msg.remove("POST /dispatch/device HTTP/1.1\r\n");
        int ind = msg.indexOf("\r\n");
        msg = msg.mid(ind+2);
        ind = msg.indexOf("\r\n");
        msg = msg.mid(ind+2);
        ind = msg.indexOf("\r\n");
        msg = msg.mid(ind+2);
        //qDebug() << qPrintable(msg);

        QJsonDocument itemDoc = QJsonDocument::fromJson(msg.toLatin1());
        QJsonObject itemObject = itemDoc.object();
        //qDebug()<<itemObject;

        QJsonObject json;
        json.insert("error", 0);
        json.insert("reason", "ok");
        json.insert("IP", "192.168.0.105");
        json.insert("port", PORT);
        QByteArray data = QJsonDocument(json).toJson().data();
        QByteArray postDataSize = QByteArray::number(data.size());

        QJsonObject jsonAck;
        jsonAck.insert("error", 0);
        jsonAck.insert("deviceid", "1000113837");
        jsonAck.insert("apikey", "111111111-1111-1111-1111-111111111111");
        QByteArray dataAck = QJsonDocument(jsonAck).toJson().data();
        //QByteArray postDataSize = QByteArray::number(dataAck.size());

        dataAck = QByteArray("{\n\"error\" : 0, \"deviceid\" : \"1000113837\", "
                  "\"apikey\" : \"111111111-1111-1111-1111-111111111111\"\n}");
        QString contLength = QString("Content-Length: %1\r\n\r\n").arg(dataAck.length());
        //qDebug() << "ans --------";
        //qDebug() << "Content-Type: application/json\r\n";
        //qDebug() << qPrintable(contLength);
        //qDebug() << dataAck;
        //sslSock->write("HTTP/1.1 200 OK\r\n");
        //sslSock->write("Server: openresty\r\n");
        //sslSock->write("Content-Type: application/json\r\n");
        //sslSock->write(qPrintable(contLength));
        //sslSock->write("Connection: keep-alive\r\n");

        dataAck = "HTTP/1.1 200 OK\r\n"
               //   "Server: openresty\r\n"
               //   "Date: Mon, 15 May 2017 01:26:00 GMT\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: 58\r\n"
                  "Connection: keep-alive\r\n\r\n"
                  "{"
                  "\"error\":0,"
                  "\"reason\":\"ok\","
                  "\"IP\":\"192.168.0.105\","
                  "\"port\":9001"
                  "}";
        qDebug() << dataAck << dataAck.length();
        sslSock->write(dataAck);
    }
    else if(msg.startsWith("GET /api/ws HTTP/1.1\r\n")){
        //qDebug() << "handleSocketReadyRead" << ba;
        qDebug() << "Switching Protocols";
        QByteArray dataAck = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: q1/L5gx6qdQ7y3UWgO/TXXXXXXA=\r\n";
        //qDebug() << dataAck << dataAck.length();
        sslSock->write(dataAck);
    }
    else if(ba.startsWith("\x81\xFE\x00\xBA\x00\x00\x00\x00")){
    //else if(msg.startsWith("\x81\xFE\x00\xBA\x00\x00\x00\x00")){
        qDebug() << "register" ;//<< ba;

        int ind = ba.indexOf("{");
        ba = ba.mid(ind);
        QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
        QJsonObject itemObject = itemDoc.object();
        qDebug()<<itemObject;
        QByteArray dataAck;
        dataAck.append(0x81);
        dataAck.append(0x54);
               dataAck.append( "{"
                             "\"error\":0,"
                             "\"deviceid\":\"1000113837\","
                             "\"apikey\":\"111111111-1111-1111-1111-111111111111\""
                             "}");

        //qDebug() << dataAck;
        sslSock->write(dataAck);

    }
    else if(ba.startsWith("\x81\xf3\x00\x00\x00\x00")){
        qDebug() << "date";
        //qDebug() << "handleSocketReadyRead" << ba;
        int ind = ba.indexOf("{");
        ba = ba.mid(ind);
        QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
        QJsonObject itemObject = itemDoc.object();
        //qDebug()<<itemObject;
        QByteArray dataAck;
        dataAck.append(0x81);
        dataAck.append(0x75);
               dataAck.append("{"
                              "\"error\":0,"
                              "\"deviceid\":\"1000113837\","
                              "\"apikey\":\"111111111-1111-1111-1111-111111111111\","
                              "\"date\":\"2017-05-15T01:26:01.498Z\""
                              "}");

        //qDebug() << dataAck;
        sslSock->write(dataAck);

    }
    else if(ba.startsWith("\x89\x80\x00\x00\x00\x00")){
        qDebug() << "PING-PONG";
        QByteArray dataAck;
        dataAck.append((char)0x8A);
        dataAck.append((char)0x00);

        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        sslSock->write(dataAck);
    }
    else{
        qDebug() << "handleSocketReadyRead" << ba;
    }

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


void Dialog::handleAcceptError(QAbstractSocket::SocketError)
{
    qDebug() << "handleAcceptError";

}
