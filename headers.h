#ifndef HEADERS_H
#define HEADERS_H

#include <QDataStream>

//网络协议头一般用一字节对齐
#pragma pack(1)

//pcap文件头 (24B)
struct PcapHeader {
    quint32 magic;  // pcap 文件标识 0xa1b2c3d4
    quint16 version_major;  //主版本号
    quint16 version_minor;  //副版本号
    qint32 thisZone;    //区域时间
    quint32 sigFigs;    //精确时间戳
    quint32 snapLen;    //最大的存储长度
    quint32 linkType;   //链路层类型

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const PcapHeader &pcapH);
    friend QDataStream & operator >> (QDataStream &stream, PcapHeader &pcapH);
};

struct TimeStamp {
    quint32 timeStamp_s;    //时间戳高位，精确到秒
    quint32 timeStamp_ms;   //时间戳地位，精确到毫秒

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const TimeStamp &ts);
    friend QDataStream & operator >> (QDataStream &stream, TimeStamp &ts);
};

//数据包头 (16B)
struct PacketHeader {
    TimeStamp ts;   //时间戳
    quint32 capLen; //数据包数据区抓取长度
    quint32 len;    //数据包数据区实际长度

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const PacketHeader &packetH);
    friend QDataStream & operator >> (QDataStream &stream, PacketHeader &packetH);
};

struct MAC {
    quint8 mac[6];

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const MAC &m);
    friend QDataStream & operator >> (QDataStream &stream, MAC &m);
};

//链路层头 (14B)
struct LinkHeader {
    MAC dstMAC;   //目的MAC地址
    MAC srcMAC;   //源MAC地址
    quint16 type;   //上一层协议类型

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const LinkHeader &linkH);
    friend QDataStream & operator >> (QDataStream &stream, LinkHeader &linkH);
};

//IP头 (20B)
struct IPHeader {
    quint8 hLen_ver;    //4 位首部长度+4 位 IP 版本号
    quint8 TOS; //服务类型
    quint16 totalLen;   //数据包长度（字节）
    quint16 ID; //数据包标识
    quint16 flag_segment;   //3 位标志位+13 位片偏移
    quint8 TTL; //生命周期
    quint8 protocol;    //协议 (TCP, UDP 或其他)
    quint16 checkSum;   //IP 首部校验和
    quint32 srcIP;  //源 IP 地址
    quint32 dstIP;  //目的 IP 地址

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const IPHeader &IPH);
    friend QDataStream & operator >> (QDataStream &stream, IPHeader &IPH);
};

//TCP头 (20B)
struct TCPHeader {
    quint16 srcPort;    //源端口号
    quint16 dstPort;    //目的端口号
    quint32 seq;    //序列号
    quint32 ack;    //确认号
    quint16 hLen_flag;  //前4位：TCP头长度；中6位:保留；后6位：标志位
    quint16 win;    //窗口大小
    quint16 checkSum;   //TCP 检验和
    quint16 urgentPtr;  //紧急指针

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const TCPHeader &TCPH);
    friend QDataStream & operator >> (QDataStream &stream, TCPHeader &TCPH);
};

//UDP头 (8B)
struct UDPHeader {
    quint16 srcPort;    //源端口号
    quint16 dstPort;    //目的端口号
    quint16 len;    //数据包长度
    quint16 checkSum;   //UDP 检验和

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const UDPHeader &UDPH);
    friend QDataStream & operator >> (QDataStream &stream, UDPHeader &UDPH);
};

#endif // HEADERS_H
