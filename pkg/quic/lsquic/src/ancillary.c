#include "ancillary.h"
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>

/*
 * sets up a socket message with ancillary information, pertaining to protocol
 * used and sets ecn value to help in congestion
 * */
void format_control_message(
    struct msghdr* msg,
    enum cmsg_opts cmsg_opts,
    const struct lsquic_out_spec* spec,
    unsigned char* buf,
    size_t bufsz)
{
    struct cmsghdr* cmsg;
    struct sockaddr_in* local_sa;
    struct sockaddr_in6* local_sa6;
    struct in_pktinfo info;
    struct in6_pktinfo info6;
    size_t control_len;

    msg->msg_control = buf;
    msg->msg_controllen = bufsz;

    /* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
     * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
     */
    memset(buf, 0, bufsz);

    control_len = 0;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg_opts && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg_opts & SEND_ADDR) {
            if (AF_INET == spec->dest_sa->sa_family) {
                local_sa = (struct sockaddr_in*)spec->local_sa;
                memset(&info, 0, sizeof(info));
                info.ipi_spec_dst = local_sa->sin_addr;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info));
                control_len += CMSG_SPACE(sizeof(info));
                memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
            } else {
                local_sa6 = (struct sockaddr_in6*)spec->local_sa;
                memset(&info6, 0, sizeof(info6));
                info6.ipi6_addr = local_sa6->sin6_addr;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
                memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
                control_len += CMSG_SPACE(sizeof(info6));
            }
            cmsg_opts &= ~SEND_ADDR;
        } else if (cmsg_opts & SEND_ECN) {
            if (AF_INET == spec->dest_sa->sa_family) {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                control_len += CMSG_SPACE(sizeof(tos));
            } else {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                control_len += CMSG_SPACE(sizeof(tos));
            }
            cmsg_opts &= ~SEND_ECN;
        } else
            assert(0);
    }

    msg->msg_controllen = control_len;
}

void read_control_message(
    struct msghdr* msg,
    struct sockaddr_storage* storage,
    uint32_t* dropped,
    int* ecn)
{
    const struct in6_pktinfo* ipv6_pkt;
    struct cmsghdr* cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        // get ip of IPV4
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ORIGDSTADDR) {
            memcpy(storage, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
        }
        // get ip of IPV6
        else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            ipv6_pkt = (void*)CMSG_DATA(cmsg);
            ((struct sockaddr_in6*)storage)->sin6_addr = ipv6_pkt->ipi6_addr;
        }
        // get dropped packets information from socket layer
        else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            memcpy(dropped, CMSG_DATA(cmsg), sizeof(*dropped));
        }
        // retrieve ECN value
        else if (
            (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
            || (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)) {
            memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
            *ecn &= IPTOS_ECN_MASK;
        }
    }
}
