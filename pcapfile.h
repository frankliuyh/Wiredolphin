#ifndef PCAPFILE_H
#define PCAPFILE_H

#include "packet.h"

struct PcapFile {
    PcapHeader pcapHeader;
    QList<Packet> packets;
};

#endif // PCAPFILE_H
