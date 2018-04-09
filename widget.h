#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include "pcapfile.h"

//一次TCP会话
struct TCPSession {
    QString key;
    QList<Packet> packets;
};

//一次UDP会话
struct UDPSession {
    QString key;
    QList<Packet> packets;
};

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();
    PcapFile m_pcapFile;  //用于存放已加载pcap文件
    QList<TCPSession> m_TCPSessions;   //用于存放提取出的TCP会话
    QList<UDPSession> m_UDPSessions;   //用于存放提取出的UDP会话

private slots:
    void on_pushButtonSrc_clicked();

    void on_pushButtonDst_clicked();

    void on_pushButtonTCPSession_clicked();

    void on_pushButtonUDPSession_clicked();

    void on_pushButtonTCPData_clicked();

    void on_pushButtonHTTPInformation_clicked();

    void on_pushButtonUDPData_clicked();

    void on_pushButtonHTTPImage_clicked();

private:
    Ui::Widget *ui;
};

#endif // WIDGET_H
