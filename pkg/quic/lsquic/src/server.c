// NOTE: In order to access struct in6_pktinfo the define bellow is necessary
#define _GNU_SOURCE
#include "openssl/base.h"
#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "address.c"
#include "cert.h"
#include "keylog.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "server.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

enum cmsg_flags {
    SEND_ADDR = 1 << 0,
    SEND_ECN = 1 << 1,
};

/* process ticker */
void reset_timer(EV_P_ ev_timer* timer, int revents);
/* ssl configuration */
static SSL_CTX* server_get_ssl_ctx(void* peer_ctx,
    const struct sockaddr* address);
/* connection methods */
static int server_packets_out(void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count);
/* add alpn value */
static void add_alpn(char* alpn, char* proto);

static const struct lsquic_stream_if stream_interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

// TODO: write a helper function to format sni from hostname, port, certkey,
// keyfile
//
//
// TODO: certify that the get_address_info function works correctly since it
// expects ip
//      address instead of a https scheme, therefore there might be a need to
//      resolve the ip

// NOTE: There should be a wrapper func to GO here
void newServer(Server* server, const char* keylog)
{
    // initialize every field with default 0
    memset(server, 0, sizeof(Server));
    server->event_loop = EV_DEFAULT;

    // registering callbacks and starting engine
    char errbuf[0x100];
    struct lsquic_engine_api engine_api;
    struct lsquic_engine_settings settings;
    settings.es_ecn = LSQUIC_DF_ECN;

    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = server_packets_out;
    engine_api.ea_packets_out_ctx = server;
    engine_api.ea_get_ssl_ctx = server_get_ssl_ctx;
    engine_api.ea_stream_if = &stream_interface;
    engine_api.ea_stream_if_ctx = server;
    engine_api.ea_settings = &settings;
    engine_api.ea_get_ssl_ctx = get_ssl_ctx;

    /* certificates */
    server->certificates = lsquic_hash_create();
    engine_api.ea_lookup_cert = lookup_cert_callback;
    engine_api.ea_cert_lu_ctx = &server->certificates;

    if (0 != lsquic_engine_check_settings(&settings, LSENG_SERVER, errbuf, sizeof(errbuf))) {
        errno = EINVAL;
        Log("invalid settings passed: %s", errbuf);
        return;
    }

    const char* keylog_dir = getenv("KEYLOG_DIR");
    setup_keylog_dir(keylog_dir);

    server->quic_engine = lsquic_engine_new(LSENG_SERVER, &engine_api);
    if (server->quic_engine == NULL) {
        // TODO: select a more appropriate errno value here
        errno = ENOPROTOOPT;
        Log("engine could not be created");
        return;
    }
}

bool add_v_server(Server* server, const char* host_name, char* port,
    const char* certkey, const char* keyfile)
{
    bool ok = load_certificate(server->certificates, host_name, certkey, keyfile, server->alpn, false);
    if (!ok) {
        Log("Failed to load certificate for %s", host_name);
        return false;
    }
    struct v_server* v_server = calloc(1, sizeof(struct v_server));
    return true;
}

/* connection methods */

void serverListen(Server* server)
{
    ev_run(server->event_loop, 0);
    ev_io_stop(server->event_loop, &server->socket_watcher);
    ev_timer_stop(server->event_loop, &server->time_watcher);
    ev_loop_destroy(server->event_loop);
    lsquic_engine_destroy(server->quic_engine);
    lsquic_global_cleanup();
    free(server->keylog_path);
}

static void read_control_message()
{
}

/*
 * sets up a socket message with ancillary information, pertaining to protocol
 * used and sets ecn value to help in congestion
 * */
static void format_control_message(struct msghdr* msg, enum cmsg_flags cw,
    const struct lsquic_out_spec* spec,
    unsigned char* buf, size_t bufsz)
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
    for (cmsg = CMSG_FIRSTHDR(msg); cw && cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cw & SEND_ADDR) {
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
            cw &= ~SEND_ADDR;
        } else if (cw & SEND_ECN) {
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
            cw &= ~SEND_ECN;
        } else
            assert(0);
    }

    msg->msg_controllen = control_len;
}

static int server_packets_out(void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count)
{
    int fd, socket_response = 0;
    struct msghdr message;
    enum cmsg_flags cw;
    union {
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
        message.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family ? sizeof(struct sockaddr_in)
                                                                      : sizeof(struct sockaddr_in6)),
        message.msg_iov = specs[n].iov;
        message.msg_iovlen = specs[n].iovlen;

        cw = SEND_ADDR;
        if (specs[n].ecn)
            cw |= SEND_ECN;
        if (cw)
            format_control_message(&message, cw, &specs[n], ancillary.buf,
                sizeof(ancillary.buf));
        else {
            message.msg_control = NULL;
            message.msg_controllen = 0;
        }

        socket_response = sendmsg(fd, &message, 0);
        if (socket_response < 0) {
            Log("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    } while (n < count);

    // TODO: not ideal way to handle this
    if (n < count)
        Log("could not send all of them");

    if (n > 0)
        return n;
    else {
        assert(socket_response < 0);
        return -1;
    }
}

/* ssl methods */

static SSL_CTX* server_get_ssl_ctx(void* peer_ctx,
    const struct sockaddr* address)
{
    SSL_CTX* ssl_ctx = (SSL_CTX*)peer_ctx;
    return ssl_ctx;
}

bool set_ssl_ctx(Server* server, const char* keylog_dir)
{
    unsigned char ticket_keys[48];

    server->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!server->ssl_ctx) {
        Log("failed to instatiate new SSL_CTX");
        return false;
    }

    SSL_CTX_set_min_proto_version(server->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(server->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(server->ssl_ctx);

    if (keylog_dir)
        SSL_CTX_set_keylog_callback(server->ssl_ctx, keylog_log_line);

    // TODO: look for certificate resumption
    return 0;
}

SSL_CTX* extract_ssl_certificate(const char* certificate, const char* keyfile)
{
    SSL_CTX* s_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!s_ssl_ctx) {
        Log("SSL_CTX_new failed");
        goto failure;
    }
    SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(s_ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, certificate)) {
        Log("SSL_CTX_use_certificate_chain_file failed");
        goto failure;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, keyfile, SSL_FILETYPE_PEM)) {
        Log("SSL_CTX_use_PrivateKey_file failed");
        goto failure;
    }
    return s_ssl_ctx;
failure:
    SSL_CTX_free(s_ssl_ctx);
    return NULL;
}

/* stream methods */

lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn)
{
    const lsquic_cid_t* cid = lsquic_conn_id(conn);
    char cid_string[0x29];
    lsquic_hexstr(cid->idbuf, cid->len, cid_string, sizeof(cid_string));
    Log("new connection %s", cid_string);
    return NULL;
}

void server_on_closed_connection(lsquic_conn_t* conn)
{
    const lsquic_cid_t* cid = lsquic_conn_id(conn);
    char cid_string[0x29];
    lsquic_hexstr(cid->idbuf, cid->len, cid_string, sizeof(cid_string));
    Log("Connection %s closed", cid_string);
}

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx,
    struct lsquic_stream* stream)
{
    return NULL;
}

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
    server_stream_ctx* const stream_data = (void*)h;
    ssize_t nread;
    unsigned char buf[1];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0) {
        stream_data->buffer[stream_data->total_size] = buf[0];
        lsquic_stream_id_t id = lsquic_stream_id(stream);
        ++stream_data->total_size;
        if (buf[0] == (unsigned char)'\n') {
            Log("read newline or filled buffer, switch to writing");
            // TODO: callback to treat data
            lsquic_stream_wantread(stream, 0);
            // lsquic_stream_wantwrite(stream, 1); // TODO: write back when it is not
            // a final response
        }
    } else if (nread == 0) {
        Log("read EOF");
        // TODO: (all data read) complete request and relay response, then shutdown
        // stream
        lsquic_stream_shutdown(stream, 0);
        if (stream_data->total_size)
            lsquic_stream_wantwrite(stream, 1);
    } else {
        /* This should not happen */
        Log("error reading from stream (errno: %d) -- abort connection", errno);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* h) { }

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* h) { }

void process_ticker(Server* server)
{
    int time_diff;
    ev_tstamp timeout;

    ev_timer_stop(server->event_loop, &server->time_watcher);
    lsquic_engine_process_conns(server->quic_engine);

    if (lsquic_engine_earliest_adv_tick(server->quic_engine, &time_diff)) {
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

void prepare_server(Server* server)
{
    if (keylog_dir) {
        struct lsquic_hash_elem* elem = lsquic_hash_first(server->certificates);
        for (; elem; elem = lsquic_hash_next(server->certificates)) {
            struct certificateElem* data = lsquic_hashelem_getdata(elem);
            SSL_CTX_set_keylog_callback(data->ssl_ctx, keylog_log_line);
        }
    }
    struct v_server* e = NULL;
    TAILQ_FOREACH(e, server->v_servers, v_server)
    {
    }
    // TODO: start v_servers
}
