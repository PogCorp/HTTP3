// NOTE: In order to access struct in6_pktinfo the define bellow is necessary
#define _GNU_SOURCE
#include "server.h"
#include "address.c"
#include "lsquic.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

// TODO: piece extracted from tut.c, determine what this is
enum ctl_what {
    CW_SENDADDR = 1 << 0,
    CW_ECN = 1 << 1,
};

/* process ticker */
void reset_timer(EV_P_ ev_timer* timer, int revents);
/* ssl configuration */
static SSL_CTX* server_get_ssl_ctx(void* peer_ctx, const struct sockaddr* address);
/* connection methods */
static int server_packets_out(void* packets_out_ctx, const struct lsquic_out_spec* specs, unsigned count);

static struct lsquic_stream_if interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

void newServer(Server* server, const char* host_name, char* port, const char* certkeym, const char* keyfile, LsquicEngine* engine)
{
    SocketAddress address;

    const int port_num = htons(atoi(port));

    get_address_info(host_name, port_num, &address);

    struct lsquic_engine_api engine_api;
    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = server_packets_out;
    engine_api.ea_packets_out_ctx = server;
    engine_api.ea_get_ssl_ctx = server_get_ssl_ctx;
    engine_api.ea_stream_if = &interface;
    engine_api.ea_stream_if_ctx = server;
}

/* connection methods */
static void
setup_control_message(struct msghdr* msg, enum ctl_what cw,
    const struct lsquic_out_spec* spec, unsigned char* buf, size_t bufsz)
{
    struct cmsghdr* cmsg;
    struct sockaddr_in* local_sa;
    struct sockaddr_in6* local_sa6;
    struct in_pktinfo info;
    struct in6_pktinfo info6;
    size_t ctl_len;

    msg->msg_control = buf;
    msg->msg_controllen = bufsz;

    /* Need to zero the buffer due to a bug(?) in CMSG_NXTHDR.  See
     * https://stackoverflow.com/questions/27601849/cmsg-nxthdr-returns-null-even-though-there-are-more-cmsghdr-objects
     */
    memset(buf, 0, bufsz);

    ctl_len = 0;
    for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cw & CW_SENDADDR) {
            if (AF_INET == spec->dest_sa->sa_family) {
                local_sa = (struct sockaddr_in*)spec->local_sa;
                memset(&info, 0, sizeof(info));
                info.ipi_spec_dst = local_sa->sin_addr;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info));
                ctl_len += CMSG_SPACE(sizeof(info));
                memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
            } else {
                local_sa6 = (struct sockaddr_in6*)spec->local_sa;
                memset(&info6, 0, sizeof(info6));
                info6.ipi6_addr = local_sa6->sin6_addr;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(info6));
                memcpy(CMSG_DATA(cmsg), &info6, sizeof(info6));
                ctl_len += CMSG_SPACE(sizeof(info6));
            }
            cw &= ~CW_SENDADDR;
        } else if (cw & CW_ECN) {
            if (AF_INET == spec->dest_sa->sa_family) {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            } else {
                const int tos = spec->ecn;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
                memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
                ctl_len += CMSG_SPACE(sizeof(tos));
            }
            cw &= ~CW_ECN;
        } else
            assert(0);
    }

    msg->msg_controllen = ctl_len;
}

static int server_packets_out(void* packets_out_ctx, const struct lsquic_out_spec* specs, unsigned count)
{
    int fd, socket_response = 0;
    struct msghdr message;
    enum ctl_what cw;
    union {
        // TODO: revise this tut.c union
        /* cmsg(3) recommends union for proper alignment */
        unsigned char buf[CMSG_SPACE(MAX(sizeof(struct in_pktinfo),
                              sizeof(struct in6_pktinfo)))
            + CMSG_SPACE(sizeof(int))];
        struct cmsghdr cmsg;
    } ancillary;

    if (0 == count)
        return 0;

    message.msg_flags = 0;
    unsigned n = 0;
    do {
        fd = (int)(uint64_t)specs[n].peer_ctx;
        message.msg_name = (void*)specs[n].dest_sa;
        message.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
        message.msg_iov = specs[n].iov;
        message.msg_iovlen = specs[n].iovlen;

        cw = CW_SENDADDR;
        if (specs[n].ecn)
            cw |= CW_ECN;
        if (cw)
            setup_control_message(&message, cw, &specs[n], ancillary.buf, sizeof(ancillary.buf));
        else {
            message.msg_control = NULL;
            message.msg_controllen = 0;
        }

        socket_response = sendmsg(fd, &message, 0);
        if (socket_response < 0) {
            log("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    } while (n < count);

    // TODO: not ideal way to handle this
    if (n < count)
        log("could not send all of them");

    if (n > 0)
        return n;
    else {
        assert(socket_response < 0);
        return -1;
    }
}

/* ssl methods */

static SSL_CTX* server_get_ssl_ctx(void* peer_ctx, const struct sockaddr* address)
{
    return NULL; // TODO: in the folder /bin of lsquic the prog.c file can help on implementation
}

SSL_CTX* extract_ssl_context(const char* certificate, const char* keyfile)
{
    SSL_CTX* s_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!s_ssl_ctx) {
        log("SSL_CTX_new failed");
        goto failure;
    }
    SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(s_ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, certificate)) {
        log("SSL_CTX_use_certificate_chain_file failed");
        goto failure;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, keyfile, SSL_FILETYPE_PEM)) {
        log("SSL_CTX_use_PrivateKey_file failed");
        goto failure;
    }
    return s_ssl_ctx;
failure:
    SSL_CTX_free(s_ssl_ctx);
    return NULL;
}

/* stream methods */

lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx, struct lsquic_conn* conn)
{
    return NULL;
}

void server_on_closed_connection(lsquic_conn_t* conn)
{
}

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx, struct lsquic_stream* stream)
{
    return NULL;
}

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void process_ticker(Server* server)
{
    int time_diff;
    ev_tstamp timeout;

    ev_timer_stop(server->event_loop, &server->time_watcher);
    lsquic_engine_process_conns(server->engine->quic_engine);

    if (lsquic_engine_earliest_adv_tick(server->engine->quic_engine, &time_diff)) {
        if (time_diff >= LSQUIC_DF_CLOCK_GRANULARITY)
            timeout = (ev_tstamp)time_diff / 1000000;
        else if (time_diff <= 0)
            timeout = 0.0;
        else
            timeout = (ev_tstamp)LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        ev_timer_init(&server->time_watcher, reset_timer, timeout, 0.);
        ev_timer_start(server->event_loop, &server->time_watcher);
    }
}

void reset_timer(EV_P_ ev_timer* timer, int revents)
{
    process_ticker(timer->data);
}
