#define _GNU_SOURCE

#include <stdint.h>
#include <sys/socket.h>

#include "lsquic.h"

enum cmsg_opts {
    SEND_ADDR = 1 << 0,
    SEND_ECN = 1 << 1,
};

void read_control_message(
    struct msghdr* msg,
    struct sockaddr_storage* storage,
    uint32_t* dropped,
    int* ecn);

/*
 * sets up a socket message with ancillary information, pertaining to protocol
 * used and sets ecn value to help in congestion
 * */
void format_control_message(
    struct msghdr* msg,
    enum cmsg_opts cmsg_opts,
    const struct lsquic_out_spec* spec,
    unsigned char* buf,
    size_t bufsz);
