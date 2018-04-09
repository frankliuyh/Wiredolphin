#ifndef PACKET_H
#define PACKET_H

#include "headers.h"

struct Packet {
    PacketHeader packetHeader;  //包头
    QByteArray packetBody;  //包体

    //友元声明，一对用于支持QDataStream 输入输出的函数
    friend QDataStream & operator << (QDataStream &stream, const Packet &packet);
    friend QDataStream & operator >> (QDataStream &stream, Packet &packet);
};

#endif // PACKET_H
