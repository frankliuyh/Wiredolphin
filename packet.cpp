#include "packet.h"

QDataStream & operator << (QDataStream &stream, const Packet &packet)
{
    stream << packet.packetHeader;
    stream.writeRawData(packet.packetBody, packet.packetHeader.capLen);

    return stream;
}

QDataStream & operator >> (QDataStream &stream, Packet &packet)
{
    stream >> packet.packetHeader;
    char *buff = new char[packet.packetHeader.capLen];
    stream.readRawData(buff, packet.packetHeader.capLen);
    packet.packetBody.setRawData(buff, packet.packetHeader.capLen);

    return stream;
}
