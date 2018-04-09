#include "headers.h"

QDataStream & operator << (QDataStream &stream, const PcapHeader &pcapH)
{
    stream << pcapH.magic;
    stream << pcapH.version_major;
    stream << pcapH.version_minor;
    stream << pcapH.thisZone;
    stream << pcapH.sigFigs;
    stream << pcapH.snapLen;
    stream << pcapH.linkType;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, PcapHeader &pcapH)
{
    stream >> pcapH.magic;
    stream >> pcapH.version_major;
    stream >> pcapH.version_minor;
    stream >> pcapH.thisZone;
    stream >> pcapH.sigFigs;
    stream >> pcapH.snapLen;
    stream >> pcapH.linkType;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const TimeStamp &ts)
{
    stream << ts.timeStamp_s;
    stream << ts.timeStamp_ms;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, TimeStamp &ts)
{
    stream >> ts.timeStamp_s;
    stream >> ts.timeStamp_ms;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const PacketHeader &packetH)
{
    stream << packetH.ts;
    stream << packetH.capLen;
    stream << packetH.len;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, PacketHeader &packetH)
{
    stream >> packetH.ts;
    stream >> packetH.capLen;
    stream >> packetH.len;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const MAC &m)
{
    for(int i = 0; i < 6; i++) stream << m.mac[i];

    return stream;
}

QDataStream & operator >> (QDataStream &stream, MAC &m)
{
    for(int i = 0; i < 6; i++) stream >> m.mac[i];

    return stream;
}

QDataStream & operator << (QDataStream &stream, const LinkHeader &linkH)
{
    stream << linkH.dstMAC;
    stream << linkH.srcMAC;
    stream << linkH.type;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, LinkHeader &linkH)
{
    stream >> linkH.dstMAC;
    stream >> linkH.srcMAC;
    stream >> linkH.type;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const IPHeader &IPH)
{
    stream << IPH.hLen_ver;
    stream << IPH.TOS;
    stream << IPH.totalLen;
    stream << IPH.ID;
    stream << IPH.flag_segment;
    stream << IPH.TTL;
    stream << IPH.protocol;
    stream << IPH.checkSum;
    stream << IPH.srcIP;
    stream << IPH.dstIP;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, IPHeader &IPH)
{
    stream >> IPH.hLen_ver;
    stream >> IPH.TOS;
    stream >> IPH.totalLen;
    stream >> IPH.ID;
    stream >> IPH.flag_segment;
    stream >> IPH.TTL;
    stream >> IPH.protocol;
    stream >> IPH.checkSum;
    stream >> IPH.srcIP;
    stream >> IPH.dstIP;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const TCPHeader &TCPH)
{
    stream << TCPH.srcPort;
    stream << TCPH.dstPort;
    stream << TCPH.seq;
    stream << TCPH.ack;
    stream << TCPH.hLen_flag;
    stream << TCPH.win;
    stream << TCPH.checkSum;
    stream << TCPH.urgentPtr;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, TCPHeader &TCPH)
{
    stream >> TCPH.srcPort;
    stream >> TCPH.dstPort;
    stream >> TCPH.seq;
    stream >> TCPH.ack;
    stream >> TCPH.hLen_flag;
    stream >> TCPH.win;
    stream >> TCPH.checkSum;
    stream >> TCPH.urgentPtr;

    return stream;
}

QDataStream & operator << (QDataStream &stream, const UDPHeader &UDPH)
{
    stream << UDPH.srcPort;
    stream << UDPH.dstPort;
    stream << UDPH.len;
    stream << UDPH.checkSum;

    return stream;
}

QDataStream & operator >> (QDataStream &stream, UDPHeader &UDPH)
{
    stream >> UDPH.srcPort;
    stream >> UDPH.dstPort;
    stream >> UDPH.len;
    stream >> UDPH.checkSum;

    return stream;
}
