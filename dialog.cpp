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


#include <QNetworkDatagram>
#include <QStringList>


#include <QtNetwork/QSslError>
//#include <QSslSocket>

// http://10.10.7.1/device
Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog),
    reply(Q_NULLPTR),
    settings("murinets", "sonoff-control"),
    udpSocket(NULL)/*,
    m_pWebSocketServer(Q_NULLPTR),
    tcpServ(this)*/
{
    ui->setupUi(this);

    ui->lineEditServerIp->setText(settings.value("servIP").toString());
    ui->lineEditSSID->setText(settings.value("SSID").toString());
    ui->lineEditKey->setText(settings.value("key").toString());
    ui->lineEditUDPport->setText(settings.value("UDP_port", 8053).toString());

    //int port = 9001;
    QFile certFile(QStringLiteral("ssl/selfcert.in.crt"));
    QFile keyFile(QStringLiteral("ssl/selfcert.in.key"));

//    QFile certFile(QStringLiteral("ssl/localhost.cert"));
//    QFile keyFile(QStringLiteral("ssl/localhost.key"));
    if(certFile.open(QIODevice::ReadOnly) == false){
        qDebug() << "certFile error";
        ui->plainTextEdit->appendPlainText("certFile error");
    }
    if(keyFile.open(QIODevice::ReadOnly) == false){
        //qDebug() << "keyFile error";
        ui->plainTextEdit->appendPlainText("keyFile error");
    }


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
        QString msg = QString("listening on port %1").arg(PORT1);
        //qDebug() << qPrintable(msg);
        ui->plainTextEdit->appendPlainText(msg);
        connect(sslServ, SIGNAL(newConnection()),  this, SLOT(handleNewSslConnection()));
        //connect(m_pWebSocketServer, &QWebSocketServer::closed, this, &EchoServer::closed);
    }
    else{
        QString msg = QString("listening on port %1 failed").arg(PORT1);
        //qDebug() << qPrintable(msg);
        ui->plainTextEdit->appendPlainText(msg);
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


    udpServerOpen();

    QStringList columnHeaderNames;
    columnHeaderNames << "id" << "type"<< "ip"<< "descr"<< "rssi"
                      << "r0"<< "r1"<< "r2"<< "r3"
                      << ""
                      << "s0"<< "s1"<< "s2"<< "s3";

    ui->tableWidget->setColumnCount(columnHeaderNames.length());
    ui->tableWidget->setHorizontalHeaderLabels(columnHeaderNames);
    ui->tableWidget->resizeColumnsToContents();

}

Dialog::~Dialog()
{
    QString ssidName = ui->lineEditSSID->text();
    QString key =  ui->lineEditKey->text();
    QString servIP =  ui->lineEditServerIp->text();

    int udpPort = ui->lineEditUDPport->text().toInt();

    settings.setValue("SSID", ssidName);
    settings.setValue("key", key);
    settings.setValue("servIP", servIP);
    settings.setValue("UDP_port", udpPort);

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
    //qDebug() << ba;
    ui->plainTextEdit->appendPlainText(QString(ba));
    /*QJsonDocument doc(QJsonDocument::fromJson(ba));
    QJsonObject json = doc.object();
    qDebug() << json["deviceid"].toString().toLatin1();
    qDebug() << json["apikey"].toString().toLatin1();
    qDebug() << json["accept"].toString().toLatin1();*/
}

void Dialog::handleHttpReadyRead()
{
    qDebug() << "handleHttpReadyRead";
}

void Dialog::handleSSLError(QNetworkReply*,QList<QSslError>)
{
    //qDebug() << "handleSSLError";
    QString msg = QString("handleSSLError");
    ui->plainTextEdit->appendPlainText(msg);
}

void Dialog::handleSSLError(QSslSocket* s, QList<QSslError> erl)
{
    QString msg = QString("handleSSLError");
    ui->plainTextEdit->appendPlainText(msg);

//    qDebug() << "handleSSLError" << s->peerAddress() <<  s->sslErrors() << erl;
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

    sslSockList.append(sslSock);
    connect(sslSock, &QSslSocket::encrypted, [=](){ handleEncrypted(sslSock);});
    //connect(sslSock, &QSslSocket::sslErrors, [this, sslSock](const QList<QSslError> &erl){/* handleSSLError(sslSock, erl);*/} );
    connect(sslSock, &QSslSocket::readyRead, [=](){ handleSslSocketReadyRead(sslSock);} );
    //connect(sslSock, &QSslSocket::sslErrors, [=](){ /*handleSSLError(sslSock, serr);*/} );
    connect(sslSock, &QSslSocket::disconnected, [=](){ handleSslSocketDisconnected(sslSock);} );

    connect(sslSock, &QSslSocket::peerVerifyError, [=](){ } );
    //connect(sslSock, &QSslSocket::sslErrors, [=](){ } );

    sslSock->setSslConfiguration(sslConfiguration);
    sslSock->startServerEncryption();


    QString msg = QString("%1 newSSLConnection").arg(sslSock->peerAddress().toString());
    //qDebug() << qPrintable(msg);
    msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
    ui->plainTextEdit->appendPlainText(msg);
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

//void Dialog::handleSocketError(QSslSocket* s, QAbstractSocket::SocketError err)
//{
    //qDebug() << "handleSocketError" << err << sslSock->sslErrors();
//    qDebug() << sslSock->sslErrors();
//    sslSock->ignoreSslErrors();

//}

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
    //qDebug() << "handlePeerVerifyError";
    QString msg = QString("handlePeerVerifyError");
    ui->plainTextEdit->appendPlainText(msg);
}

void Dialog::handleSslSocketReadyRead(QSslSocket* s)
{
    QByteArray ba = s->readAll();
    QString msg(ba);
    if(msg.startsWith("POST /dispatch/device HTTP/1.1\r\n")){
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
                  "Content-Length: 82\r\n"
                  "Connection: keep-alive\r\n\r\n";
        QString dataAckStr;
        dataAckStr.sprintf("HTTP/1.1 200 OK\r\n"
                           //   "Server: openresty\r\n"
                           //   "Date: Mon, 15 May 2017 01:26:00 GMT\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: %d\r\n"
                              "Connection: keep-alive\r\n\r\n", data.length());
        dataAck = dataAckStr.toLatin1();
        dataAck += data;

        s->write(dataAck);

        QString msg = QString("%1 dispatch/device").arg(s->peerAddress().toString());
        //qDebug() << qPrintable(msg);
        //qDebug() << "handleSocketReadyRead" << ba;
        msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
        ui->plainTextEdit->appendPlainText(msg);
    }
    else if(msg.startsWith("GET /api/ws HTTP/1.1\r\n")){
        QByteArray dataAck = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: q1/L5gx6qdQ7y3UWgO/TXXXXXXA=\r\n";
        //qDebug() << dataAck << dataAck.length();
        s->write(dataAck);

        QString msg = QString("%1 Switching Protocols").arg(s->peerAddress().toString());
        //qDebug() << qPrintable(msg);
        msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
        ui->plainTextEdit->appendPlainText(msg);
    }
    else if(ba[0] == 0x81){
        int ind = ba.indexOf("{");
        ba = ba.mid(ind);
        QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
        QJsonObject io = itemDoc.object();
        //qDebug() << s->peerAddress() <<itemObject;

        QString devIdStr = io["deviceid"].toString();
        devIdMap[devIdStr] = s;

        QString mdl = io["model"].toString();



        QJsonObject jsonAck;
        jsonAck["error"] = 0;
        jsonAck["deviceid"] = devIdStr;
        jsonAck["apikey"] = "111111111-1111-1111-1111-111111111111";

        TSonoffDevData *tsdd = devDataMap[devIdStr];
        if(tsdd == NULL){
            tsdd = new TSonoffDevData;
            devDataMap.insert(devIdStr, tsdd);
            tsdd->devId = devIdStr;
            tsdd->id = devDataMap.keys().size();
            tsdd->rowIndex = -1;
            tsdd->typeStr = mdl;
            tsdd->ha = s->peerAddress();

            tsdd->type = unknown;
            if(mdl.compare("PSF-A04-GL") == 0){
                tsdd->type = PSFA04GL;
            }
            else if(mdl.compare("ITA-GZ1-GL") == 0){
                tsdd->type = ITAGZ1GL;
            }
            else if(mdl.compare("PSA-B01-GL") == 0){
                tsdd->type = PSAB01GL;
            }

            for(int i=0; i<4; i++){
                QPushButton *pb = new QPushButton("na");
                tsdd->pb[i] = pb;
                connect(pb, &QPushButton::clicked, [=](){ turnRele(devIdStr, pb, i);});

                pb = new QPushButton("na");
                tsdd->srartupStatePb[i] = pb;
                connect(pb, &QPushButton::clicked, [=](){
                    TStartupType startUpState = OFF;
                    if(pb->text() == "off"){                        
                        startUpState = ON;
                        pb->setText("on");
                    }
                    else if(pb->text() == "on"){
                        startUpState = STAY;
                        pb->setText("stay");
                    }
                    else if(pb->text() == "stay"){
                        startUpState = OFF;
                        pb->setText("off");
                    }
                    turnStartUpRele(devIdStr, i, startUpState); /*turnRele(devIdStr, pb, i);*/
                });
            }

            tsdd->twiRssi = NULL;


        }

        updateTable();

        if(io.contains("action")){
            if(io["action"].toString() == "update"){
                //qDebug() << s->peerAddress() << "update" << qPrintable(io["params"].toObject()["switch"].toString());
                //qDebug() << io;

                QString msg = QString("%1 update %2").arg(s->peerAddress().toString()).arg(io["params"].toObject()["switch"].toString());
                //qDebug() << qPrintable(msg);
                msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
                ui->plainTextEdit->appendPlainText(msg);
                //ui->plainTextEdit->appendPlainText(io);

                wsSendJson(s, jsonAck);

                int rssi = io["params"].toObject()["rssi"].toInt(-99);
                if(tsdd->twiRssi != NULL){
                    tsdd->twiRssi->setText(QString("%1").arg(rssi));
                }
                //qDebug() << rssi;
                QString swStr;
                switch(tsdd->type){
                case ITAGZ1GL:
                case PSAB01GL:
                    swStr = io["params"].toObject()["switch"].toString();
                    tsdd->pb[0]->setText(swStr);

                    swStr = io["params"].toObject()["startup"].toString();
                    tsdd->srartupStatePb[0]->setText(swStr);
                    break;
                case PSFA04GL:
                    //qDebug() << io["params"].toObject()["switches"];
                    for(int i=0; i<4; i++){
                        swStr = io["params"].toObject()["switches"].toArray()[i].toObject()["switch"].toString();
                        tsdd->pb[i]->setText(swStr);
                    }
                    break;
                }

            }
            else if(io["action"].toString().compare("register") == 0){
                wsSendJson(s, jsonAck);

                QString msg = QString("%1 register %2").arg(s->peerAddress().toString()).arg(mdl);
                msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
                ui->plainTextEdit->appendPlainText(msg);
            }
            else if(io["action"].toString().compare("date") == 0){
                jsonAck["date"] = "2017-05-15T01:26:01.498Z";
                wsSendJson(s, jsonAck);

                QString msg = QString("%1 date").arg(s->peerAddress().toString());
                msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
                ui->plainTextEdit->appendPlainText(msg);
            }
            else if(io["action"].toString().compare("query") == 0){
                jsonAck["params"] = 0;
                wsSendJson(s, jsonAck);

                QString msg = QString("%1 query").arg(s->peerAddress().toString());
                msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
                ui->plainTextEdit->appendPlainText(msg);
            }
        }
        else if(io.contains("error")){
            //qDebug() << s->peerAddress()  << "respond:" << io["error"].toString().toInt() /*<< "seq:" << io["sequence"].toString()*/;

            int err = io["error"].toString().toInt();
            if(err == 0){
            }
            else{
            }
            QString msg = QString("%1 respond %2").arg(s->peerAddress().toString()).arg(err);
            msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
            ui->plainTextEdit->appendPlainText(msg);
        }
        else{
            //qDebug() << s->peerAddress()  << "unknown" << ba;

            QString msg = QString("%1 unknown").arg(s->peerAddress().toString());
            msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
            ui->plainTextEdit->appendPlainText(msg);
        }
    }
    else if(ba[0] == 0x89){
        QByteArray dataAck;
        dataAck.append((char)0x8A);
        dataAck.append((char)0x00);

        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        dataAck.append((char)0x00);
        s->write(dataAck);

        QString msg = QString("%1 p-p").arg(s->peerAddress().toString());
        //qDebug() << s->peerAddress() << "PING-PONG" << QTime::currentTime().toString("mm:ss:zzz");
        msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
        //ui->plainTextEdit->appendPlainText(msg);

    }
    else{        
        QString msg = QString("%1 handleSocketReadyRead %2").arg(s->peerAddress().toString()).arg(QString(ba));
        //qDebug() << s->peerAddress()  << "handleSocketReadyRead" << ba;
        msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
        ui->plainTextEdit->appendPlainText(msg);

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

//void Dialog::handleSocketReadyRead()
//{
//    QByteArray ba = tcpSock->readAll();
//    QJsonDocument itemDoc = QJsonDocument::fromJson(ba);
//    QJsonObject rootObj = itemDoc.object();

//    qDebug() << "handleSocketReadyRead" << ba;

////    QUrl url(QString("http://192.168.0.102/ap"));
////    QNetworkRequest request(url);

//////    QByteArray jsonString = "{\n\"version\": 4,"
//////                "\"ssid\": \"TL-WR842ND\","
//////                "\"password\": \"kkkknnnn\","
//////                "\"serverName\": \"192.168.0.105\","
//////                "\"port\": 80\n}";

////    //QByteArray postDataSize = QByteArray::number(jsonString.size());


////    QJsonObject json;
////    json.insert("error", 0);
////    json.insert("deviceid", "TL-WR842ND");
////    json.insert("apikey", "111111111-1111-1111-1111-111111111111");

////    QByteArray data = QJsonDocument(json).toJson().data();
////    QByteArray postDataSize = QByteArray::number(data.size());
////    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
////    request.setHeader(QNetworkRequest::ContentLengthHeader, postDataSize);


////    tcpSock->write();
////    reply = qnam.post(request, data);

////    connect(reply, SIGNAL(finished()), this, SLOT(handleHttpFinished()));
////    connect(reply, SIGNAL(error(QNetworkReply::NetworkError)), this, SLOT(handleReplyError(QNetworkReply::NetworkError)));
////    connect(reply, &QIODevice::readyRead, this, &Dialog::handleHttpReadyRead);


//}

//void Dialog::handleSocketDisconnected()
//{
//    qDebug() << "handleSocketDisconnected";
//}

void Dialog::handleSslSocketDisconnected(QSslSocket* s)
{    
    QString msg = QString("%1 sslSocketDisconnected").arg(s->peerAddress().toString());
    msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
    ui->plainTextEdit->appendPlainText(msg);
}

void Dialog::handleEncrypted(QSslSocket* s)
{
//    QString msg = QString("%1 encrypted").arg(s->peerAddress().toString());
//    //qDebug() << qPrintable(msg);
//    ui->plainTextEdit->appendPlainText(msg);

    QString msg = QString("%1 encrypted").arg(s->peerAddress().toString());
    //qDebug() << qPrintable(msg);
    msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
    ui->plainTextEdit->appendPlainText(msg);
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

//    QByteArray jsonString = "{\n\"version\": 4,"
//                "\"ssid\": \"Redmi\","
//                "\"password\": \"kkkknnnn\","
//                "\"serverName\": \"192.168.43.250\","
//                "\"port\": 9001\n}";

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


    //qnam.op
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
    QString msg = QString("handleAcceptError");
    ui->plainTextEdit->appendPlainText(msg);

}


void Dialog::turnRele(QString devId, int id, bool bEna)
{
    QSslSocket* s = devIdMap[devId];
    TDevTypes devType = devDataMap[devId]->type;
    if((devType == ITAGZ1GL)||(devType == PSAB01GL)){
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
    else if(devType == PSFA04GL){

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
}

void Dialog::turnStartUpRele(QString devId, int id, TStartupType startUpState)
{
    QSslSocket* s = devIdMap[devId];
    TDevTypes devType = devDataMap[devId]->type;
    if((devType == ITAGZ1GL)||(devType == PSAB01GL)){
        QJsonObject paramJson;

        switch(startUpState){
        case ON:
            paramJson["startup"] = "on";
            break;
        case OFF:
            paramJson["startup"] = "off";
            break;
        case STAY:
            paramJson["startup"] = "stay";
            break;
        }

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
    else if(devType == PSFA04GL){
    }


}

void Dialog::updateTable()
{
    QTableWidget *tw = ui->tableWidget;
    //tw->clearContents();
    QList<QString> keys = devDataMap.keys();

    foreach (QString dId, keys) {
        if(devDataMap[dId]->rowIndex == -1){
            int rId = tw->rowCount();
            devDataMap[dId]->rowIndex = rId;
            tw->insertRow(rId);
            QTableWidgetItem *twi = new QTableWidgetItem(dId);
            twi->setFlags(twi->flags() &  ~Qt::ItemIsEditable);
            tw->setItem(rId, 0, twi);
            twi = new QTableWidgetItem(devDataMap[dId]->typeStr);
            twi->setFlags(twi->flags() &  ~Qt::ItemIsEditable);
            tw->setItem(rId, 1, twi);
            twi = new QTableWidgetItem(devDataMap[dId]->ha.toString());
            twi->setFlags(twi->flags() &  ~Qt::ItemIsEditable);
            tw->setItem(rId, 2, twi);

            QString descr = settings.value(dId).toString();
            twi = new QTableWidgetItem(descr);
            twi->setTextAlignment(Qt::AlignCenter);
            tw->setItem(rId, 3, twi);

            twi = new QTableWidgetItem();
            twi->setTextAlignment(Qt::AlignCenter);
            twi->setFlags(twi->flags() &  ~Qt::ItemIsEditable);
            tw->setItem(rId, 4, twi);
            devDataMap[dId]->twiRssi = twi;


            if((devDataMap[dId]->type == ITAGZ1GL) ||
               (devDataMap[dId]->type == PSAB01GL)){
                QPushButton *pb = devDataMap[dId]->pb[0];
                tw->setCellWidget(rId, 5, pb);
                //devDataMap[dId]->pb[0] = pb;

                pb = devDataMap[dId]->srartupStatePb[0];
                tw->setCellWidget(rId, 10, pb);
            }
            else if(devDataMap[dId]->type == PSFA04GL){
                for(int i=0; i<4; i++){
                    QPushButton *pb = devDataMap[dId]->pb[i];
                    tw->setCellWidget(rId, 5+i, pb);
                }
            }

        }

//        for(int i=0; i<tw->rowCount(); i++){
//            QString s = ((QTableWidgetItem*)tw->cellWidget(i, 0))->text();
//            if(s==dId){
//            }
//        }

    }
//    int addRowsCount = (keys.size()-tw->rowCount());
//    for(int i=0; i<addRowsCount; i++){

//    }

    for(int id=0; id<keys.length(); id++){
        QString devIdStr = keys[id];
        TSonoffDevData &devData = *(devDataMap[devIdStr]);
//        QLabel *l = new QLabel(devIdStr);
//        l->setAlignment(Qt::AlignCenter);
//        ui->tableWidget->setCellWidget(id, 0, l);
//        l = new QLabel("type");
//        ui->tableWidget->setCellWidget(id, 1, l);

        if((devData.type == ITAGZ1GL) ||
           (devData.type == PSAB01GL)){
//            QPushButton *pb = devData.pb[0];
//            tw->setCellWidget(id, 2, pb);
//            devData.pb[0] = pb;
        }
        else if(devData.type == PSFA04GL){
            for(int i=0; i<4; i++){
//                QPushButton *pb = devData.pb[i];
//                tw->setCellWidget(id, 2+i, pb);
            }
        }
    }
    tw->resizeColumnsToContents();
}

void Dialog::turnRele(QString devIdStr, QPushButton *pb, int releId)
{
    //qDebug() << devIdStr << pb->text() << releId;

    bool bOn = false;
    if(pb->text() == "off"){
        bOn = true;
        pb->setText("on");
    }
    else{
        bOn = false;
        pb->setText("off");
    }

    TSonoffDevData &dd = *devDataMap[devIdStr];
    if(dd.type == PSFA04GL){
        turnRele(devIdStr, releId, bOn);
    }
    else if((dd.type == ITAGZ1GL) || (dd.type == PSAB01GL)){        
        turnRele(devIdStr, 0, bOn);
    }
}

void Dialog::udpServerOpen()
{
    if(udpSocket == NULL){
        int udpPort = ui->lineEditUDPport->text().toInt();
        udpSocket = new QUdpSocket(this);
//        connect(udpSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
//                this, SLOT(stateChanged(QAbstractSocket::SocketState)));

        QString msg;

        if(udpSocket->bind(QHostAddress::Any, udpPort) == true){
            //qDebug("UDP bind OK");
            msg.sprintf("UDP on %d bind OK", udpPort);
        }
        else{
            msg.sprintf("UDP on %d bind FAIL", udpPort);
        }
        ui->plainTextEdit->appendPlainText(msg);

        connect(udpSocket, SIGNAL(readyRead()),
                this, SLOT(handleUpdPendingDatagrams()));
    }
}

void Dialog::udpServerClose()
{
    udpSocket->close();
    disconnect(udpSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
               this, SLOT(stateChanged(QAbstractSocket::SocketState)));
    disconnect(udpSocket, SIGNAL(readyRead()),
               this, SLOT(readPendingDatagrams()));
    ui->plainTextEdit->appendPlainText("UDP closed");

}

void Dialog::handleUpdPendingDatagrams()
{
    while (udpSocket->hasPendingDatagrams()) {
//        dataGramCnt++;
        QNetworkDatagram datagram = udpSocket->receiveDatagram();
        //qDebug() << datagram.data();
        QString msg(datagram.data());


        QString msgText = QString("UDP: %1:%2").arg(udpSocket->peerAddress().toString()).arg(msg);
        //qDebug() << qPrintable(msg);
        msgText = QTime::currentTime().toString("hh:mm:ss")+"> " + msgText;
        ui->plainTextEdit->appendPlainText(msgText);

        QStringList msgParts = msg.split(":");
        if(msgParts.length() < 2)
            continue;
        QString deviceId = msgParts[0];
        if(deviceId.length() != 10){
            msgText = QString("UDP: devId len err %1").arg(deviceId.length());
            msgText = QTime::currentTime().toString("hh:mm:ss")+"> " + msgText;
            ui->plainTextEdit->appendPlainText(msgText);
            continue;
        }

        for(int i=1; i<msgParts.length(); i++){
            QString cmd = msgParts[i];
            QStringList cmdParts = cmd.split("->");
            if(cmdParts.length()!=2)
                continue;
            int releInd = cmdParts[0].toInt();
            if( (releInd<0) || (releInd>3)){
                continue;
            }
            if(cmdParts[1].length() != 1)
                continue;
            bool releEna = false;
            if(cmdParts[1] == 'e'){
                releEna = true;
            }
            else if(cmdParts[1] == 'd'){
                releEna = false;
            }
            else{
                continue;
            }
            turnRele(deviceId, releInd, releEna);
        }
    }
}

void Dialog::on_tableWidget_itemChanged(QTableWidgetItem *item)
{
    if(item->column() == 3){
        //qDebug() << item->row() << item->column()<< item->text();
        QList<QString> keys = devDataMap.keys();

        foreach (QString dId, keys) {
            if(devDataMap[dId]->rowIndex == item->row()){
                QString descr = item->text();

                settings.setValue(dId, descr);

                QString msg = QString("%1 set description \"%2\" ").arg(dId).arg(descr);
                //qDebug() << qPrintable(dId) << item->text();
                msg = QTime::currentTime().toString("hh:mm:ss")+"> " + msg;
                ui->plainTextEdit->appendPlainText(msg);
                ui->tableWidget->resizeColumnsToContents();
                break;
            }

        }
    }
}

void Dialog::on_tableWidget_cellChanged(int row, int column)
{
    //qDebug() << row << column << ((QTableWidgetItem*)ui->tableWidget->cellWidget(row, column))->text();
}
