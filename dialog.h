#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QAuthenticator>
#include <QWebSocket>
#include <QTcpServer>
#include <QWebSocketServer>
#include <sslserver.h>
#include <QMap>
namespace Ui {
class Dialog;
}
QT_FORWARD_DECLARE_CLASS(QWebSocketServer)
QT_FORWARD_DECLARE_CLASS(QWebSocket)

#define PORT 9001
class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private:
    Ui::Dialog *ui;

    QTimer timer;
    QNetworkAccessManager qnam;

    QNetworkReply *reply;

    QSslConfiguration sslConfiguration;

    //QWebSocketServer *m_pWebSocketServer;
    QTcpServer *tcpServ;
    QTcpSocket *tcpSock;
    QList<QSslSocket*> sslSockList;
    SslServer *sslServ;

    QList<QWebSocket *> m_clients;

    QMap<QSslSocket*, QString> devIdMap;

    //QWebSocket m_deb_client;

    //QSslSocket *m_sslSocket;
    //QMap<QSslSocket*, >
    void wsSendJson(QTcpSocket *s, QJsonObject);

    void turnRele(QSslSocket*,bool);

private slots:
    void handleTimer();
    void slotAuthenticationRequired(QNetworkReply*,QAuthenticator *authenticator);
    void handleHttpFinished();
    void handleHttpReadyRead();

    void handleReplyError(QNetworkReply::NetworkError);

    void onNewConnection();
    void onNewSslConnection();

    void handleWSNwConn();

    void onWebSocketConnected();
    void onWebSocketClosed();


    void on_pushButtonSendReg_clicked();
    void on_pushButtonGetReq_clicked();
    void handleQNmFinished(QNetworkReply*);
    void handleSSLError(QNetworkReply*,QList<QSslError>);
    void handleSSLError(QSslSocket*, QList<QSslError>);
    void handleSslSocketDisconnected(QSslSocket*);
    void handleSslSocketReadyRead(QSslSocket*);

    void handleSocketError(QSslSocket*, QAbstractSocket::SocketError);
    void handleSocketReadyRead();
    void handleSocketDisconnected();

    void handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator *authenticator);
    void handlePeerVerifyError(const QSslError &error);
    void handleServerError(QWebSocketProtocol::CloseCode closeCode);
    void handleEncrypted(QSslSocket*);

    void handleAcceptError(QAbstractSocket::SocketError);

    void on_pushButton_clicked();
    void on_pushButton_2_clicked();
};

#endif // DIALOG_H
