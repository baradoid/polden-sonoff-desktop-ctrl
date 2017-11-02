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

typedef enum {
    unknown,
    ITAGZ1GL, //1ch basic
    PSFA04GL, //4ch
    PSAB01GL
} TDevTypes;

#define PORT1 9001
#define PORT2 9002
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
    QMap<QSslSocket*, TDevTypes> devTypeMap;

    //QWebSocket m_deb_client;

    //QSslSocket *m_sslSocket;
    //QMap<QSslSocket*, >
    void wsSendJson(QTcpSocket *s, QJsonObject);

    void turnRele(QSslSocket*,bool);
    void sendApReq(int port);

private slots:
    void handleTimer();
    void slotAuthenticationRequired(QNetworkReply*,QAuthenticator *authenticator);
    void handleHttpFinished();
    void handleHttpReadyRead();

    void handleReplyError(QNetworkReply::NetworkError);

    void handleNewSslConnection();

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
    void on_pushButtonSendReg2_clicked();

    void handleNewTcpConnection();
};

#endif // DIALOG_H
