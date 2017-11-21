#include "dialog.h"
#include "ui_dialog.h"
#include <QDebug>
#include <QUrl>
#include "QtWebSockets/qwebsocketserver.h"
#include "QtWebSockets/qwebsocket.h"
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
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

    ui->lineEditServerIp->setText("192.168.0.105");
    //int port = 9001;
    QFile certFile(QStringLiteral("ssl/selfcert.in.crt"));
    QFile keyFile(QStringLiteral("ssl/selfcert.in.key"));

//    QFile certFile(QStringLiteral("ssl/localhost.cert"));
//    QFile keyFile(QStringLiteral("ssl/localhost.key"));
    if(certFile.open(QIODevice::ReadOnly) == false)
        qDebug() << "certFile error";
    if(keyFile.open(QIODevice::ReadOnly) == false)
        qDebug() << "keyFile error";


    QSslCertificate certificate(&certFile, QSsl::Pem);
    QSslKey sslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
    certFile.close();
    keyFile.close();

    //sslConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);
    sslConfiguration.setLocalCertificate(certificate);
    sslConfiguration.setPrivateKey(sslKey);
    //sslConfiguration.setProtocol(QSsl::AnyProtocol);
    //sslConfiguration.setProtocol(QSsl::TlsV1_2);

    sslServ = new SslServer(this);
    if (sslServ->listen(QHostAddress::Any, PORT1)) {
        qDebug() << "listening on port" << PORT1;
        connect(sslServ, SIGNAL(newConnection()),  this, SLOT(handleNewSslConnection()));
        //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
    }

//    tcpServ = new QTcpServer(this);
//    if (tcpServ->listen(QHostAddress::Any, PORT2)) {
//        qDebug() << "listening on port" << PORT2;
//        connect(tcpServ, SIGNAL(newConnection()),  this, SLOT(handleNewTcpConnection()));
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

void Dialog::handleSSLError(QSslSocket* s, QList<QSslError> erl)
{
    qDebug() << "handleSSLError" << s->peerAddress() <<  s->sslErrors() << erl;
}

//void Dialog::onNewConnection()
//{
//    tcpSock = tcpServ->nextPendingConnection();
//    //    //sslSock->ignoreSslErrors();
//    connect(tcpSock, SIGNAL(readyRead()),
//            this, SLOT(handleSocketReadyRead()));
//    connect(tcpSock, SIGNAL(error(QAbstractSocket::SocketError)),
//            this, SLOT(handleSocketError(QAbstractSocket::SocketError)));
//    connect(tcpSock, SIGNAL(disconnected()),
//            this, SLOT(handleSocketDisconnected()));

//    //serverStatusLabel->setText(tr("Accepted connection"));
//    //tcpServer.close();
//}

void Dialog::handleWSNwConn()
{
    //QWebSocket *ws = m_pWebSocketServer->nextPendingConnection();

    qDebug() << "handleWSNwConn";
}

void Dialog::handleNewSslConnection()
{

    QSslSocket *sslSock = (QSslSocket*)sslServ->nextPendingConnection();

    qDebug() << "onNewSSLConnection" << sslSock->peerAddress();
    sslSockList.append(sslSock);
    connect(sslSock, &QSslSocket::encrypted, [=](){ handleEncrypted(sslSock);});
    //connect(sslSock, &QSslSocket::sslErrors, [this, sslSock](const QList<QSslError> &erl){ handleSSLError(sslSock, erl);} );
    connect(sslSock, &QSslSocket::readyRead, [=](){ handleSslSocketReadyRead(sslSock);} );
    //connect(sslSock, &QSslSocket::error, [=](QAbstractSocket::SocketError serr){ handleSocketError(sslSock, serr);} );
    connect(sslSock, &QSslSocket::disconnected, [=](){ handleSslSocketDisconnected(sslSock);} );

    sslSock->setSslConfiguration(sslConfiguration);
    sslSock->startServerEncryption();
}

void Dialog::handleNewTcpConnection()
{
//    tcpSock = tcpServ->nextPendingConnection();
//    qDebug() << "handleNewTcpConnection" << tcpSock->peerAddress();

//    //    //sslSock->ignoreSslErrors();
//    connect(tcpSock, SIGNAL(readyRead()),
//            this, SLOT(handleSocketReadyRead()));
//    connect(tcpSock, SIGNAL(error(QAbstractSocket::SocketError)),
//            this, SLOT(handleSocketError(QAbstractSocket::SocketError)));
//    connect(tcpSock, SIGNAL(disconnected()),
//            this, SLOT(handleSocketDisconnected()));
}

void Dialog::handleSocketError(QSslSocket* s, QAbstractSocket::SocketError err)
{
    //qDebug() << "handleSocketError" << err << sslSock->sslErrors();
//    qDebug() << sslSock->sslErrors();
//    sslSock->ignoreSslErrors();

}

//void Dialog::handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator *authenticator)
//{
//    qDebug() << "handleOriginAuthenticationRequired" ;
//}

//void Dialog::handleServerError(QWebSocketProtocol::CloseCode closeCode)
//{
//    qDebug() << "handleServerError" ;
//}

void Dialog::handlePeerVerifyError(const QSslError &error)
{
    qDebug() << "handlePeerVerifyError";
}

void Dialog::handleSslSocketReadyRead(QSslSocket* s)
{
    QByteArray ba = s->readAll();
    QString msg(ba);
    if(msg.startsWith("POST /dispatch/device HTTP/1.1\r\n")){
        qDebug() << s->peerAddress()  << "dispatch/device";
        qDebug() << "handleSocketReadyRead" << ba;
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
        //qDebug()<< s->peerAddress()<<itemObject;
        //qDebug()<< s->peerAddress()<< itemObject["deviceid"] << itemObject["deviceid"].toString();
        QString devIdStr = itemObject["deviceid"].toString();
        devIdMap[devIdStr] = s;
        //qDebug() << devIdMap;

        QString servIp = ui->lineEditServerIp->text();
        QJsonObject json;
        json.insert("error", 0);
        json.insert("reason", "ok");
        json.insert("IP", servIp);
        json.insert("port", PORT1);
        QByteArray data = QJsonDocument(json).toJson().data();
        QByteArray dataAck;
        dataAck = "HTTP/1.1 200 OK\r\n"
               //   "Server: openresty\r\n"
               //   "Date: Mon, 15 May 2017 01:26:00 GMT\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: 84\r\n"
                  "Connection: keep-alive\r\n\r\n";
        dataAck += data;

        s->write(dataAck);
    }
    else if(msg.startsWith("GET /api/ws HTTP/1.1\r\n")){
        //qDebug() << "handleSocketReadyRead" << ba;
        qDebug() << s->peerAddress()  << "Switching Protocols";
        QByteArray dataAck = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: q1/L5gx6qdQ7y3UWgO/TXXXXXXA=\r\n";
        //qDebug() << dataAck << dataAck.length();
        s->write(dataAck);
    }
    else if(ba[0] == 0x81){
        int ind = ba.indexOf("{");
        ba = ba.mid(ind);
        QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
        QJsonObject io = itemDoc.object();
        //qDebug() << s->peerAddress() <<itemObject;

        QString devIdStr = io["deviceid"].toString();
        devIdMap[devIdStr] = s;
        QJsonObject jsonAck;
        jsonAck["error"] = 0;
        jsonAck["deviceid"] = devIdStr;
        jsonAck["apikey"] = "111111111-1111-1111-1111-111111111111";

        if(io.contains("action")){
            if(io["action"].toString().compare("update") == 0){
                qDebug() << s->peerAddress() << "update" << qPrintable(io["params"].toObject()["switch"].toString());
                qDebug() << io;
                wsSendJson(s, jsonAck);
                if(devTypeMap[devIdStr] == PSFA04GL){
                    qDebug() << "PSFA04GL" << io["params"].toObject()["switches"];

                }
            }
            else if(io["action"].toString().compare("register") == 0){
                //if()
                devTypeMap[devIdStr] = unknown;
                QString mdl = io["model"].toString();
                if(mdl.compare("PSF-A04-GL") == 0){
                    devTypeMap[devIdStr] = PSFA04GL;
                }
                else if(mdl.compare("ITA-GZ1-GL") == 0){
                    devTypeMap[devIdStr] = ITAGZ1GL;
                }
                else if(mdl.compare("PSA-B01-GL") == 0){
                    devTypeMap[devIdStr] = PSAB01GL;
                }


                qDebug() << s->peerAddress() << "register" << mdl; //<< qPrintable(itemObject["params"].toObject()["switch"].toString());
                //qDebug() << mdl;
                //qDebug() << s->peerAddress() << "register" << qPrintable(io["params"].toString());
                wsSendJson(s, jsonAck);
            }
            else if(io["action"].toString().compare("date") == 0){
                qDebug() << s->peerAddress() << "date";
                jsonAck["date"] = "2017-05-15T01:26:01.498Z";
                wsSendJson(s, jsonAck);
            }
            else if(io["action"].toString().compare("query") == 0){
                qDebug() << s->peerAddress() << "query";
                //qDebug() << io;
                jsonAck["params"] = 0;
                wsSendJson(s, jsonAck);
            }
        }
        else if(io.contains("error")){
            qDebug() << s->peerAddress()  << "respond:" << io["error"].toString().toInt() /*<< "seq:" << io["sequence"].toString()*/;
        }
        else{
            qDebug() << s->peerAddress()  << "unknown" << ba;
        }
    }
    else if(ba[0] == 0x89){
        qDebug() << s->peerAddress() << "PING-PONG" << QTime::currentTime().toString("mm:ss:zzz");
        QByteArray dataAck;
        dataAck.append((char)0x8A);
        dataAck.append((char)0x00);

        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        s->write(dataAck);
    }
    else{
        qDebug() << s->peerAddress()  << "handleSocketReadyRead" << ba;

    }

}

void Dialog::wsSendJson(QTcpSocket *s, QJsonObject json)
{
    //\x81\xFE\x00\xBA\x00\x00\x00\x00
    QByteArray jsonBa = QJsonDocument(json).toJson().data();

    QByteArray dataAck;
    dataAck.append(0x81);
    if(jsonBa.size() < 126){
        dataAck.append((char)(jsonBa.size()));
    }
    else{
        quint16 jsonBaSize = jsonBa.size();
        dataAck.append((char)0x7e);
        dataAck.append((char)((jsonBaSize>>8)&0xff));
        dataAck.append((char)(jsonBaSize&0xff));
//        qDebug() <<
//                    "!!!!!!!!!!!!!!!!!!";
    }
    dataAck += jsonBa;

    //qDebug() << dataAck;
    s->write(dataAck);

}

void Dialog::handleSocketReadyRead()
{
    QByteArray ba = tcpSock->readAll();
    QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
    QJsonObject rootObj = itemDoc.object();

    qDebug() << "handleSocketReadyRead" << ba;

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

void Dialog::handleSslSocketDisconnected(QSslSocket* s)
{
    qDebug() << "sslSocketDisconnected" << s->peerAddress();
}

void Dialog::handleEncrypted(QSslSocket* s)
{
    qDebug()  << "handleEncrypted" << s->peerAddress();
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

void Dialog::sendApReq(int port)
{
    QString ssid = ui->lineEditSSID->text();
    QString key = ui->lineEditKey->text();
    QString servIp = ui->lineEditServerIp->text();

    QUrl url(QString("http://10.10.7.1/ap"));
    QNetworkRequest request(url);

    QByteArray jsonString = "{\n\"version\": 4,"
                "\"ssid\": \"Redmi\","
                "\"password\": \"kkkknnnn\","
                "\"serverName\": \"192.168.43.250\","
                "\"port\": 9001\n}";

    //QByteArray postDataSize = QByteArray::number(jsonString.size());

    QJsonObject json;
    json.insert("version", 4);
    //json.insert("ssid", "TL-WR842ND");
    //json.insert("password", "kkkknnnn");
    //json.insert("serverName", "192.168.0.105");
//    json.insert("ssid", "tech.10");
//    json.insert("password", "1Polden4FX");
//    json.insert("serverName", "192.168.0.2");
      json.insert("ssid", ssid);
      json.insert("password", key);
      json.insert("serverName", servIp);

    json.insert("port", PORT1);

    QByteArray data = QJsonDocument(json).toJson().data();

    //data = jsonString;
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

void Dialog::on_pushButtonSendReg_clicked()
{
    sendApReq(PORT1);
}

void Dialog::on_pushButtonSendReg2_clicked()
{
    //sendApReq(PORT2);
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

void Dialog::turnRele(QString devId, QSslSocket* s, bool bEna)
{
    QJsonObject paramJson;
    if(bEna)
        paramJson["switch"] = "on";
    else
        paramJson["switch"] = "off";

    QJsonObject json;
    json["action"] = "update";
    json["deviceid"] = devId;
    json["apikey"] = "111111111-1111-1111-1111-111111111111";
    //json["userAgent"] = "app";
    //json["sequence"] = "1494806715179";
    //json["ts"] = 0;
    //json["from"] = "app";

    json["params"] = paramJson;

    //qDebug() << QJsonDocument(json).toJson().data();
    wsSendJson(s, json);
}

void Dialog::turnRele(QString devId, QSslSocket* s, int id, bool bEna)
{
    QJsonArray jsonArr;
    QJsonObject paramJson;
    paramJson["outlet"] = id;
    paramJson["switch"] = bEna?"on":"off";

    jsonArr.append(paramJson);
//    paramJson["outlet"] = 1;
//    jsonArr.append(paramJson);
//    paramJson["outlet"] = 2;
//    jsonArr.append(paramJson);
//    paramJson["outlet"] = 3;
//    jsonArr.append(paramJson);


    QJsonObject jsonSwitches;
    jsonSwitches["switches"] = jsonArr;
    QJsonObject json;
    json["action"] = "update";
    json["deviceid"] = devId;
    json["apikey"] = "111111111-1111-1111-1111-111111111111";
    //json["userAgent"] = "app";
    //json["sequence"] = "1494806715179";
    //json["ts"] = 0;
    //json["from"] = "app";

    json["params"] = jsonSwitches;

    //qDebug() << QJsonDocument(json).toJson().data();
    wsSendJson(s, json);
}

void Dialog::on_pushButton_clicked()
{
    foreach (QString devId, devIdMap.keys()) {
        if(devTypeMap[devId] == ITAGZ1GL){
            turnRele(devId, devIdMap[devId], true);
        }
        if(devTypeMap[devId] == PSAB01GL){
            turnRele(devId, devIdMap[devId], true);
        }


    }
}

void Dialog::on_pushButton_2_clicked()
{
    foreach (QString devId, devIdMap.keys()) {
        if(devTypeMap[devId] == ITAGZ1GL){
            turnRele(devId, devIdMap[devId], false);
        }
        if(devTypeMap[devId] == PSAB01GL){
            turnRele(devId, devIdMap[devId], false);
        }


    }
}


void Dialog::on_pushButtonReg1On_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {

        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 0, true);
        }
//        turnRele(s, 1, true);
//        turnRele(s, 2, true);
//        turnRele(s, 3, true);
    }

}

void Dialog::on_pushButtonReg1Off_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 0, false);
        }
    }
}

void Dialog::on_pushButtonReg2On_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 1, true);
        }
    }
}

void Dialog::on_pushButtonReg2Off_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 1, false);
        }
    }
}

void Dialog::on_pushButtonReg3On_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 2, true);
        }
    }
}

void Dialog::on_pushButtonReg3Off_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 2, false);
        }
    }
}

void Dialog::on_pushButtonReg4On_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 3, true);
        }
    }
}

void Dialog::on_pushButtonReg4Off_clicked()
{
    foreach (QString devIdStr, devIdMap.keys()) {
        if(devTypeMap[devIdStr] == PSFA04GL){
            turnRele(devIdStr, devIdMap[devIdStr], 3, false);
        }
    }
}
