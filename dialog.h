#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QAuthenticator>
//#include <QWebSocket>
#include <QTcpServer>
//#include <QWebSocketServer>
#include <sslserver.h>
#include <QMap>
#include <QSettings>
#include <QUdpSocket>
#include <QTableWidgetItem>

namespace Ui {
class Dialog;
}
QT_FORWARD_DECLARE_CLASS(QWebSocketServer)
QT_FORWARD_DECLARE_CLASS(QWebSocket)

typedef enum {
    unknown,
    ITAGZ1GL, //1ch basic
    PSFA04GL, //4ch
    PSAB01GL  //smart socket
} TDevTypes;

typedef struct{
    int id;
    QString devId;
    TDevTypes type;
    QString typeStr;
    QPushButton *pb[4];
    int rowIndex;
    QHostAddress ha;
    QTableWidgetItem *twiRssi;
    QPushButton *srartupStatePb[4];
} TSonoffDevData;

#define PORT1 9001
//#define PORT2 9002
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
    //QTcpServer *tcpServ;
    QTcpSocket *tcpSock;
    QList<QSslSocket*> sslSockList;
    SslServer *sslServ;

    QList<QWebSocket *> m_clients;

    QMap<QString, QSslSocket* > devIdMap;
    //QMap<QString, TDevTypes> devTypeMap;
    QMap<QString, TSonoffDevData*> devDataMap;

    QSettings settings;

    QUdpSocket *udpSocket;

    //QWebSocket m_deb_client;

    //QSslSocket *m_sslSocket;
    //QMap<QSslSocket*, >
    void wsSendJson(QTcpSocket *s, QJsonObject);

    void turnRele(QString devId, int, bool);
    void sendApReq(int port);

    void updateTable();

    void udpServerOpen();
    void udpServerClose();
    void turnRele(QString, QPushButton*, int);
    void turnStartUpRele(QString devId, int id, bool bEna);

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

//    void handleSocketError(QSslSocket*, QAbstractSocket::SocketError);
    //void handleSocketReadyRead();
    //void handleSocketDisconnected();

    //void handleOriginAuthenticationRequired(QWebSocketCorsAuthenticator *authenticator);
    void handlePeerVerifyError(const QSslError &error);
    //void handleServerError(QWebSocketProtocol::CloseCode closeCode);
    void handleEncrypted(QSslSocket*);

    void handleAcceptError(QAbstractSocket::SocketError);


    void handleNewTcpConnection();       
    void handleUpdPendingDatagrams();


    void on_tableWidget_itemChanged(QTableWidgetItem *item);
    void on_tableWidget_cellChanged(int row, int column);
};

#endif // DIALOG_H
