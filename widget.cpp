#include "widget.h"
#include "ui_widget.h"
#include "httpkey.h"
#include <QMessageBox>
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QDataStream>  //串行化数据流
#include <QTextStream>  //文本流
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QEventLoop>
#include <string.h>
#include <stdio.h>

#define PCAP_MAGIC 0xa1b2c3d4
#define TCP_FLAG 6
#define UDP_FLAG 17
#define BUFSIZE 10240
#define STRSIZE 1024

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    this->setWindowTitle("Wiredolphin");
}

Widget::~Widget()
{
    delete ui;
}

//选取路径加载pcap文件
void Widget::on_pushButtonSrc_clicked()
{
    //获取打开文件名
    QString strFileName = QFileDialog::getOpenFileName(this,
                                                       tr("打开pcap文件"),
                                                       tr("."),
                                                       tr("Pcap files(*.pcap);;All files(*)"));
    //判断文件名
    if( strFileName.isEmpty() )
        return;
    //在界面上显示路径
    ui->lineEditSrc->setText(strFileName);
    //定义文件对象
    QFile fileIn(strFileName);
    //打开
    if( ! fileIn.open(QIODevice::ReadOnly) )
    {
        QMessageBox::warning(this, tr("打开pcap文件"), tr("打开指定pcap文件失败：") + fileIn.errorString());
        return;
    }
    //定义串行化输入流
    QDataStream dsIn(&fileIn);
    dsIn.setByteOrder(QDataStream::LittleEndian);   //按小字节序进行读取
    //读取pcap文件头
    dsIn >> m_pcapFile.pcapHeader;
    if( m_pcapFile.pcapHeader.magic !=  PCAP_MAGIC ) //文件标识号不符
    {
        QMessageBox::warning(this, tr("Error"), tr("读取pcap文件出错！"));
        return;
    }
    //到达文件末尾前循环读取数据包
    while( ! dsIn.atEnd() )
    {
        Packet packet;
        dsIn >> packet.packetHeader;    //读取包头
        char *buff = new char[packet.packetHeader.capLen];  //分配缓冲区空间，大小为数据包中数据区（除包头以外）的大小，即包体大小
        dsIn.readRawData(buff, packet.packetHeader.capLen); //读取包体数据至缓冲区
        packet.packetBody.setRawData(buff, packet.packetHeader.capLen); //设置包体
        //将得到的数据包存入m_pcapFile中的成员变量packets数组中
        m_pcapFile.packets.append(packet);
    }
    //清空之前提取的会话
    m_TCPSessions.clear();
    m_UDPSessions.clear();
    //反馈信息
    ui->labelFeedback->setText("pcap文件加载成功！");

    return;
}

//设置工作区路径
void Widget::on_pushButtonDst_clicked()
{
    //获取工作区路径
    QString workspace = QFileDialog::getExistingDirectory(this, tr("请选择工作区"), tr("."));
    //在界面上显示路径
    ui->lineEditDst->setText(workspace);
    if( ! workspace.isEmpty() )
    {
        ui->labelFeedback->setText("设置工作区成功！");
    }

    return;
}

//提取TCP会话
void Widget::on_pushButtonTCPSession_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_TCPSessions.isEmpty() )
    {
        //提取TCP会话
        QMap<QString, QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i < m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == TCP_FLAG){
                 //创建五元组
                TCPHeader tcpheader;
                dspacketbody >> tcpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(tcpheader.srcPort);
                port2 = QString::number(tcpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "TCP Session-" + ip1 + + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            TCPSession tcpS;
            tcpS.key = nkey.at(i);
            tcpS.packets = packets;
            m_TCPSessions.append(tcpS);
        }
    }

    if( m_TCPSessions.count() < 1 )
    {
        QMessageBox::warning(this, tr("提取TCP会话"), tr("pcap文件中不存在TCP会话！"));
        return;
    }


    //将会话保存到pcap文件
    for(int i = 0; i < m_TCPSessions.count(); i++)
    {
        QString strFileName = ui->lineEditDst->text();
        //创建TCP Sessions文件夹
        QDir dir(strFileName);
        dir.mkdir("TCP Sessions");
        strFileName = strFileName + "/TCP Sessions/" + m_TCPSessions.at(i).key + ".pcap";
        QFile fileOut(strFileName);
        if( ! fileOut.open(QIODevice::WriteOnly) )
        {
            QMessageBox::warning(this, tr("提取TCP会话"), tr("提取TCP会话文件失败：") + fileOut.errorString());
            return;
        }
        //定义串行化输入流
        QDataStream dsOut(&fileOut);
        dsOut.setByteOrder(QDataStream::LittleEndian);   //按小字节序进行写入
        dsOut << m_pcapFile.pcapHeader;
        for(int j = 0; j < m_TCPSessions.at(i).packets.count(); j++)
        {
            dsOut << m_TCPSessions.at(i).packets.at(j);
        }
    }
    ui->labelFeedback->setText("提取TCP会话成功！");

    return;
}

//提取UDP会话
void Widget::on_pushButtonUDPSession_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_UDPSessions.isEmpty() )
    {
        //提取UDP会话
        QMap<QString,QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i<m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == UDP_FLAG){
                 //创建五元组
                UDPHeader udpheader;
                dspacketbody >> udpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(udpheader.srcPort);
                port2 = QString::number(udpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "UDP Session-" + ip1 + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            UDPSession udpS;
            udpS.key = nkey.at(i);
            udpS.packets = packets;
            m_UDPSessions.append(udpS);
        }
    }

    if( m_UDPSessions.count() < 1 )
    {
        QMessageBox::warning(this, tr("提取UDP会话"), tr("pcap文件中不存在UDP会话！"));
        return;
    }

    //将会话保存到pcap文件
    for(int i = 0; i < m_UDPSessions.count(); i++)
    {
        QString strFileName = ui->lineEditDst->text();
        //创建UDP Sessions文件夹
        QDir dir(strFileName);
        dir.mkdir("UDP Sessions");
        strFileName = strFileName + "/UDP Sessions/" + m_UDPSessions.at(i).key + ".pcap";
        QFile fileOut(strFileName);
        if( ! fileOut.open(QIODevice::WriteOnly) )
        {
            QMessageBox::warning(this, tr("提取UDP会话"), tr("提取UDP会话文件失败：") + fileOut.errorString());
            return;
        }
        //定义串行化输入流
        QDataStream dsOut(&fileOut);
        dsOut.setByteOrder(QDataStream::LittleEndian);   //按小字节序进行写入
        dsOut << m_pcapFile.pcapHeader;
        for(int j = 0; j < m_UDPSessions.at(i).packets.count(); j++)
        {
            dsOut << m_UDPSessions.at(i).packets.at(j);
        }
    }
    ui->labelFeedback->setText("提取UDP会话成功！");

    return;
}

//提取TCP负载
void Widget::on_pushButtonTCPData_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_TCPSessions.isEmpty() )
    {
        //提取TCP会话
        QMap<QString, QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i < m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == TCP_FLAG){
                 //创建五元组
                TCPHeader tcpheader;
                dspacketbody >> tcpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(tcpheader.srcPort);
                port2 = QString::number(tcpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "TCP Session-" + ip1 + + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            TCPSession tcpS;
            tcpS.key = nkey.at(i);
            tcpS.packets = packets;
            m_TCPSessions.append(tcpS);
        }
    }

    if( m_TCPSessions.count() < 1 )
    {
        QMessageBox::warning(this, tr("提取TCP负载"), tr("pcap文件中不存在TCP会话！"));
        return;
    }

    //循环遍历每一个TCP会话
    for(int i = 0; i < m_TCPSessions.count(); i++)
    {
        TCPSession tcpS = m_TCPSessions.at(i);  //取出第i个TCP会话
        //生成会话负载文件名
        QString strFileName = ui->lineEditDst->text();
        //创建TCP Data文件夹
        QDir dir(strFileName);
        dir.mkdir("TCP Data");
        strFileName += "/TCP Data/" + tcpS.key.replace(4, 7, "Data") + ".txt";
        //生成串行数据流写文件
        QFile fileOut(strFileName);
        if( ! fileOut.open(QIODevice::WriteOnly) )
        {
            QMessageBox::warning(this, tr("提取TCP负载"), tr("提取TCP负载文件失败：") + fileOut.errorString());
            return;
        }
        QTextStream tsOut(&fileOut);
        //循环遍历一次会话中所有数据包
        for(int j = 0; j < tcpS.packets.count(); j++)
        {
            Packet packet = tcpS.packets.at(j); //取出第j个数据包
            QDataStream dsTCPDataOut(packet.packetBody);    //生成串行数据流获取负载
            LinkHeader linkH;
            IPHeader ipH;
            TCPHeader tcpH;
            //按顺序读取负载前面的三个头
            dsTCPDataOut >> linkH;
            dsTCPDataOut >> ipH;
            dsTCPDataOut >> tcpH;
            int tcpHdrLen = 4 * (tcpH.hLen_flag >> 12); //计算TCP头长度
            QByteArray tcpData;
            int dataLen = ipH.totalLen - 20 - 20;  //TCP头可选部分加上负载的总长度
            char *buff = new char[dataLen]; //分配缓冲区
            dsTCPDataOut.readRawData(buff, dataLen);
            tcpData.setRawData(buff, dataLen);
            //如果TCP头有可选部分
            if( tcpHdrLen > 20)
            {
                tcpData = tcpData.right(dataLen - (tcpHdrLen - 20));    //去除数据中的TCP头可选部分
            }
            //如果负载数据不为空，则写入文件中
            if( ! tcpData.isEmpty())
            {
                //tcpData 是原始字节数组，人为不可读，转为十六进制字符串
                //QString tcpDataString = tcpData.toHex();
                //将负载字符串写入文件中
                tsOut << tcpData << endl;
            }
        }
    }
    ui->labelFeedback->setText("提取TCP负载成功！");

    return;
}

//提取HTTP信息
void Widget::on_pushButtonHTTPInformation_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_TCPSessions.isEmpty() )
    {
        //提取TCP会话
        QMap<QString, QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i < m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == TCP_FLAG){
                 //创建五元组
                TCPHeader tcpheader;
                dspacketbody >> tcpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(tcpheader.srcPort);
                port2 = QString::number(tcpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "TCP Session-" + ip1 + + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            TCPSession tcpS;
            tcpS.key = nkey.at(i);
            tcpS.packets = packets;
            m_TCPSessions.append(tcpS);
        }
    }

    int i, j,flag;
    int sessionsNum, packetsNum;
    int host_len, uri_len;
    quint16 http_len;
    char buf[BUFSIZE];
    FILE* fp;
    QList<Packet> packets;
    quint16 ip_len;
    quint32 src_ipt[4];
    quint32 dst_ipt[4];
    quint16 dst_port, src_port, tcp_flags;
    struct LinkHeader macHeader;
    struct IPHeader ipHeader;
    struct TCPHeader tcpHeader;
    PacketHeader packetHeader;  //包头
    QByteArray packetData;      //包体
    sessionsNum = m_TCPSessions.size();
    i = 0,j = 0;
    flag = 0;
    // printf("%d:  src=%x\n", i, tcp_flags);
    if(sessionsNum < 1)
    {
        QMessageBox::warning(this, tr("提取HTTP关键信息"), tr("pcap文件中不存在TCP会话！"));
        return;
    }
    //生成会话负载文件名
    QString strFileName = ui->lineEditDst->text();
    strFileName += "/HTTP Key Information.txt";
    if((fp = fopen(strFileName.toStdString().c_str(),"w")) == NULL)
    {
        QMessageBox::warning(this, tr("Error"), tr("无法生成HTTP关键信息文件！"));
        return;
    }
    for(i = 0; i < sessionsNum; i++)
    {
        packets = (m_TCPSessions.at(i)).packets;
        packetsNum = packets.size();
        if(packetsNum < 1)
        {
            //printf("No packets in the session!!!");
            ui->labelFeedback->setText("No packets in the session!!!");
            return;
        }
        for(j = 0; j < packetsNum; j++)
        {
            packetHeader = packets.value(j).packetHeader;
            packetData = packets.value(j).packetBody;
            if(packetData.size() < 1)
                break;
            QDataStream bds(packetData);
            bds >> macHeader;
            bds >> ipHeader;
            bds >> tcpHeader;
            tcp_flags = tcpHeader.hLen_flag&0x3f;
            dst_port = tcpHeader.dstPort;
            src_port = tcpHeader.srcPort;
            ip_len = ipHeader.totalLen;
            //将ip由二进制转为标准形式
            src_ipt[0] = ipHeader.srcIP >> 24;
            src_ipt[1] = (ipHeader.srcIP >> 16) & 0x00ff;
            src_ipt[2] = (ipHeader.srcIP >> 8) & 0x0000ff;
            src_ipt[3] = ipHeader.srcIP & 0x000000ff;
            dst_ipt[0] = ipHeader.dstIP >> 24;
            dst_ipt[1] = (ipHeader.dstIP >> 16) & 0x00ff;
            dst_ipt[2] = (ipHeader.dstIP >> 8) & 0x0000ff;
            dst_ipt[3] = ipHeader.dstIP & 0x000000ff;
            if(tcp_flags == 0x18) // (PSH, ACK) 3路握手成功后
            {
                if(dst_port == 80) // HTTP GET请求
                {
                    flag = 0;
                    http_len = ip_len - 40; //http 报文长度
                    uri_len = HttpKeyData(packetData.right(http_len), "GET ", "HTTP", buf); //查找 uri值
                    if(uri_len > 1)
                    {
                        buf[uri_len] = '\0';
                        //printf("GET: %s",buf);
                        if(fprintf(fp, "%d.%d.%d.%d[%d]->%d.%d.%d.%d[%d] GET: %s \t",src_ipt[0],src_ipt[1],src_ipt[2],src_ipt[3],src_port,dst_ipt[0],dst_ipt[1],dst_ipt[2],dst_ipt[3],dst_port,buf) != 1)
                        {
                            ui->labelFeedback->setText("output file can not write");
                        }
                    }
                    else
                        flag = 1;
                    host_len = HttpKeyData(packetData.right(http_len), "Host: ", "\r\n", buf); //查找 host 值
                    if(host_len > 1)
                    {
                        if(flag == 0)
                        {
                            buf[host_len] = '\0';
                            //printf("HOST: %s", buf);
                            if(fprintf(fp, "Host: %s",buf) != 1)
                            {
                                ui->labelFeedback->setText("output file can not write");
                            }
                        }
                        else
                        {
                            buf[host_len] = '\0';
                            if(fprintf(fp, "%d.%d.%d.%d[%d]->%d.%d.%d.%d[%d] GET: \t Host: %s",src_ipt[0],src_ipt[1],src_ipt[2],src_ipt[3],src_port,dst_ipt[0],dst_ipt[1],dst_ipt[2],dst_ipt[3],dst_port,buf) != 1)
                            {
                                ui->labelFeedback->setText("output file can not write");
                            }
                        }
                    }
                }
            }
        } // end for
    }
    fclose(fp);
    ui->labelFeedback->setText("提取HTTP协议中的关键信息成功！");
    return;
}

//提取UDP负载
void Widget::on_pushButtonUDPData_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_UDPSessions.isEmpty() )
    {
        //提取UDP会话
        QMap<QString,QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i<m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == UDP_FLAG){
                 //创建五元组
                UDPHeader udpheader;
                dspacketbody >> udpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(udpheader.srcPort);
                port2 = QString::number(udpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "UDP Session-" + ip1 + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            UDPSession udpS;
            udpS.key = nkey.at(i);
            udpS.packets = packets;
            m_UDPSessions.append(udpS);
        }
    }

    if( m_UDPSessions.count() < 1 )
    {
        QMessageBox::warning(this, tr("提取UDP负载"), tr("pcap文件中不存在UDP会话！"));
        return;
    }

    //循环遍历每一个UDP会话
    for(int i = 0; i < m_UDPSessions.count(); i++)
    {
        UDPSession udpS = m_UDPSessions.at(i);  //取出第i个TCP会话
        //生成会话负载文件名
        QString strFileName = ui->lineEditDst->text();
        //创建TCP Data文件夹
        QDir dir(strFileName);
        dir.mkdir("UDP Data");
        strFileName += "/UDP Data/" + udpS.key.replace(4, 7, "Data") + ".txt";
        //生成串行数据流写文件
        QFile fileOut(strFileName);
        if( ! fileOut.open(QIODevice::WriteOnly) )
        {
            QMessageBox::warning(this, tr("提取UDP负载"), tr("提取UDP负载文件失败：") + fileOut.errorString());
            return;
        }
        QTextStream tsOut(&fileOut);
        //循环遍历一次会话中所有数据包
        for(int j = 0; j < udpS.packets.count(); j++)
        {
            Packet packet = udpS.packets.at(j); //取出第j个数据包
            QDataStream dsUDPDataOut(packet.packetBody);    //生成串行数据流获取负载
            LinkHeader linkH;
            IPHeader ipH;
            UDPHeader udpH;
            //按顺序读取负载前面的三个头
            dsUDPDataOut >> linkH;
            dsUDPDataOut >> ipH;
            dsUDPDataOut >> udpH;
            QByteArray udpData;
            int dataLen = ipH.totalLen - 20 - 8;  //UDP负载的长度
            char *buff = new char[dataLen]; //分配缓冲区
            dsUDPDataOut.readRawData(buff, dataLen);
            udpData.setRawData(buff, dataLen);
            //如果负载数据不为空，则写入文件中
            if( ! udpData.isEmpty())
            {
                //udpData 是原始字节数组，人为不可读，转为十六进制字符串
                //QString udpDataString = udpData.toHex();
                //将负载字符串写入文件中
                tsOut << udpData << endl;
            }
        }
    }
    ui->labelFeedback->setText("提取UDP负载成功！");

    return;
}

void Widget::on_pushButtonHTTPImage_clicked()
{
    //判断是否打开pcap文件并设置工作区
    if( ui->lineEditSrc->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请选择pcap文件！"));
        return;
    }
    if( ui->lineEditDst->text().isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("请设置工作区！"));
        return;
    }

    if( m_TCPSessions.isEmpty() )
    {
        //提取TCP会话
        QMap<QString, QList<Packet>> map;
        QString keyTemp;
        QStringList nkey;
        LinkHeader linkheader;
        IPHeader ipheader;
        for(int i=0; i < m_pcapFile.packets.count(); i++){
            QDataStream dspacketbody(m_pcapFile.packets.at(i).packetBody);
            dspacketbody.setByteOrder(QDataStream::BigEndian);
            dspacketbody >> linkheader;
            dspacketbody >> ipheader;
            if (ipheader.protocol == TCP_FLAG){
                 //创建五元组
                TCPHeader tcpheader;
                dspacketbody >> tcpheader;
                QString ip1,ip2,port1,port2;
                //将ip由二进制转为标准形式
                quint32 temp;
                temp = ipheader.srcIP >> 24;
                ip1 = QString::number(temp);
                temp = (ipheader.srcIP >> 16) & 0x00ff;
                ip1 += "." + QString::number(temp);
                temp = (ipheader.srcIP >> 8) & 0x0000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.srcIP & 0x000000ff;
                ip1 += "." + QString::number(temp);
                temp = ipheader.dstIP >> 24;
                ip2 = QString::number(temp);
                temp = (ipheader.dstIP >> 16) & 0x00ff;
                ip2 += "." + QString::number(temp);
                temp = (ipheader.dstIP >> 8) & 0x0000ff;
                ip2 += "." + QString::number(temp);
                temp = ipheader.dstIP & 0x000000ff;
                ip2 += "." + QString::number(temp);
                port1 = QString::number(tcpheader.srcPort);
                port2 = QString::number(tcpheader.dstPort);
                if( ip1 > ip2 )
                {
                    QString temp;
                    temp = ip1;
                    ip1 = ip2;
                    ip2 = temp;
                    temp = port1;
                    port1 = port2;
                    port2 = temp;
                }
                keyTemp = "TCP Session-" + ip1 + + "[" + port1 + "]~" + ip2 + "[" + port2 + "]";
                if( ! nkey.contains(keyTemp) )
                {
                    nkey.append(keyTemp);
                }
                if (map.contains(keyTemp)){
                    map[keyTemp].append(m_pcapFile.packets.at(i));//加入已有的key对应的value中
                }else{
                    QList<Packet> packets;
                    packets.append(m_pcapFile.packets.at(i));
                    map.insert(keyTemp, packets);//新建
                }
            }
        }
        //转换
        for(int i = 0; i < nkey.count(); i++) {
            QList<Packet> packets = map[nkey.at(i)];
            TCPSession tcpS;
            tcpS.key = nkey.at(i);
            tcpS.packets = packets;
            m_TCPSessions.append(tcpS);
        }
    }

    if( m_TCPSessions.count() < 1 )
    {
        QMessageBox::warning(this, tr("还原HTTP图片"), tr("pcap文件中不存在TCP会话！"));
        return;
    }

    QStringList imagesURI;
    int i, j;
    int sessionsNum, packetsNum;
    quint16 http_len;
    QList<Packet> packets;
    quint16 ip_len;
    quint16 dst_port, tcp_flags;
    struct LinkHeader macHeader;
    struct IPHeader ipHeader;
    struct TCPHeader tcpHeader;
    PacketHeader packetHeader;  //包头
    QByteArray packetData;      //包体
    sessionsNum = m_TCPSessions.size();
    i = 0,j = 0;
    // printf("%d:  src=%x\n", i, tcp_flags);
    if(sessionsNum < 1)
    {
        QMessageBox::warning(this, tr("Error"), tr("pcap文件中没有TCP会话！"));
        return;
    }
    for(i = 0; i < sessionsNum; i++)
    {
        packets = (m_TCPSessions.at(i)).packets;
        packetsNum = packets.size();
        if(packetsNum < 1)
        {
            //printf("No packets in the session!!!");
            ui->labelFeedback->setText("No packets in the session!!!");
            return;
        }
        for(j = 0; j < packetsNum; j++)
        {
            packetHeader = packets.value(j).packetHeader;
            packetData = packets.value(j).packetBody;
            if(packetData.size() < 1)
                break;
            QDataStream bds(packetData);
            bds >> macHeader;
            bds >> ipHeader;
            bds >> tcpHeader;
            tcp_flags = tcpHeader.hLen_flag&0x3f;
            dst_port = tcpHeader.dstPort;
            ip_len = ipHeader.totalLen;
            if(tcp_flags == 0x18) // (PSH, ACK) 3路握手成功后
            {
                if(dst_port == 80) // HTTP GET请求
                {
                    http_len = ip_len - 40; //http 报文长度
                    QByteArray httpString = packetData.right(http_len);
                    //获取Full Request URI
                    if(httpString.contains("GET ") && httpString.contains(" HTTP")
                            && httpString.contains("Host: ") && httpString.contains("Connection: "))
                    {
                        int len1 = httpString.indexOf("GET ");
                        int len2 = httpString.indexOf(" HTTP");
                        QByteArray fileString = httpString.mid(len1 + 4, len2 - len1 - 4);
                        len1 = httpString.indexOf("Host: ");
                        len2 = httpString.indexOf("Connection: ");
                        QByteArray hostString = httpString.mid(len1 + 6, len2 - len1 - 8);
                        //如果请求为图片，则储存该URI
                        if( fileString.contains(".jpg") || fileString.contains(".gif") )
                        {
                            QByteArray uri = "http://" + hostString + fileString;
                            QString str(uri);
                            if( ! imagesURI.contains(str) )
                            {
                                imagesURI.append(str);
                            }
                        }
                    }
                }
            }
        }
    }// end for
    QString strFileName = ui->lineEditDst->text();
    QDir dir(strFileName);
    dir.mkdir("Images");
    for(int i = 0; i < imagesURI.count(); i++)
    {
        QString uri = imagesURI.at(i);
        QString temp = uri.right(uri.size() - uri.lastIndexOf("/"));    //文件名
        //去掉.gif后面的内容
        if( temp.contains(".gif") )
        {
            if( ! temp.endsWith(".gif") )
            {
                int len = temp.indexOf(".gif");
                QString name = temp.left(temp.size() - len - 4);
                temp = temp.right(temp.size() - name.size());
                temp = temp.replace(0, 1, "-");
                name = name.left(name.size() - 4);
                temp = name + temp + ".gif";
            }
        }
        QString imageName = strFileName + "/Images" + temp;
        QFile fileOut(imageName);
        if( ! fileOut.open(QIODevice::WriteOnly) )
        {
            QMessageBox::warning(this, tr("还原HTTP图片"), tr("还原HTTP图片文件失败：") + fileOut.errorString());
            continue;
        }
        QNetworkAccessManager manager;
        QNetworkRequest request;
        request.setUrl(uri);
        QNetworkReply *reply = manager.get(request);

        //等待传输完毕
        QEventLoop loop;
        QObject::connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
        loop.exec();

        if (reply->error() != QNetworkReply::NoError)
        {
            QMessageBox::warning(this, tr("Error"), tr("还原第%1张图片文件出错！").arg(i));
            continue;
        }
        //将得到的数据写入文件中
        fileOut.write(reply->readAll());
        fileOut.close();
        delete reply;
    }
    ui->labelFeedback->setText("还原HTTP图片成功！");

    return;
}
