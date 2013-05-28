#ifndef RAWSOCKET_H
#define RAWSOCKET_H

#define END_OF_STREAM "thank you for testing\n"
#define PACKET_SIZE 1000

struct raw_result {
    unsigned int seconds;
    unsigned int useconds;
    unsigned int packets;
    unsigned int bytes;
    unsigned int sequence;
};

#endif
