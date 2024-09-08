// NOTE: In order to access struct in6_pktinfo the define bellow is necessary
#define _GNU_SOURCE

#include "openssl/base.h"
#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <unistd.h>

#include "address.c"
#include "ancillary.h"
#include "cert.h"
#include "keylog.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "server.h"

/* process ticker */
void reset_timer(EV_P_ ev_timer* timer, int revents);
void process_ticker(Server* server);

/* ssl configuration */
static SSL_CTX* server_get_ssl_ctx(
    void* peer_ctx,
    const struct sockaddr* address);

/* add ALPN value */
static bool add_alpn(char* alpn, char* proto);

/* handlers for send failure */
void handle_send_failure(Server* server, int fd);
void schedule_resend(EV_P_ ev_io* ev_write, int revents);

static const struct lsquic_stream_if stream_interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

// NOTE: There should be a wrapper func to GO here
void new_server(
    Server* server,
    const char* keylog,
    char** alpn_protos,
    size_t* alpn_str_size,
    int alpn_proto_len)
{
    // initialize every field with default 0
    memset(server, 0, sizeof(Server));
    server->event_loop = EV_DEFAULT;

    // registering callbacks and starting engine
    char errbuf[0x100];
    struct lsquic_engine_api engine_api;
    struct lsquic_engine_settings settings;
    settings.es_ecn = LSQUIC_DF_ECN;
    if (alpn_protos && alpn_str_size && alpn_proto_len > 0)
        for (int i = 0; i < alpn_proto_len; i++) {
            enum lsquic_version ver = lsquic_str2ver(alpn_protos[i], alpn_str_size[i]);
            settings.es_versions = 1 << ver;
            add_alpn(server->alpn, alpn_protos[i]);
        }
    else
        settings.es_versions = 1 << LSQVER_I001; // default to version 1 of QUIC

    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = server_write_socket;
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

// cleanup all virtual servers and event loop
void server_cleanup(Server* server)
{
    struct v_server* e = NULL;
    TAILQ_FOREACH(e, server->v_servers, v_server)
    {
        if (server->event_loop) {
            ev_io_stop(server->event_loop, &e->socket_watcher);
        }
        if (e->socket_descriptor >= 0)
            close(e->socket_descriptor);
        packet_buffer_cleanup(e->buffer);
    }

    ev_timer_stop(server->event_loop, &server->time_watcher);
    ev_loop_destroy(server->event_loop);
    lsquic_engine_destroy(server->quic_engine);
    lsquic_global_cleanup();
}

bool server_listen(Server* server)
{
    bool ok = server_prepare(server);
    if (!ok) {
        Log("failed to prepare server in %s", __func__);
        return false;
    }

    ev_run(server->event_loop, 0);
    server_cleanup(server);
    return true;
}

/*
 * Format used for ALPN
 * ┌───┬───┬───┬──────┐
 * │ 2 │ h │ 3 │ .... │
 * └─┬─┴─┬─┴─┬─┴──────┘
 *   │   │   │
 *   │   └─> proto value
 *   │
 *   └─> lenght of proto
 * */
static bool add_alpn(char* alpn, char* proto)
{
    size_t proto_len, alpn_len;

    proto_len = strlen(proto);
    if (proto_len > ALPN_LEN)
        return false;
    alpn_len = strlen(alpn);
    if (alpn_len + 1 + proto_len + 1 > ALPN_LEN)
        return false;

    alpn[alpn_len] = proto_len;
    memcpy(&alpn[alpn_len + 1], proto, proto_len);
    alpn[alpn_len + 1 + proto_len] = '\0';
    return true;
}

bool add_v_server(Server* server, const char* uri,
    const char* certkey, const char* keyfile)
{
    char* address = strdup(uri);
    char *host, *port;

    bool ok = validate_uri(address, &host, &port);
    if (!ok) {
        Log("Failed to validate uri: %s", uri);
        free(address);
        return false;
    }

    ok = load_certificate(server->certificates, host, certkey, keyfile, server->alpn, false);
    if (!ok) {
        Log("Failed to load certificate for %s", host);
        free(address);
        return false;
    }

    struct v_server* v_server = calloc(1, sizeof(struct v_server));
    v_server_set_address_info(v_server, host, port);
    ok = v_server_configure_socket(v_server);
    if (!ok) {
        Log("failed to configure socket for %s", uri);
        free(v_server);
        return false;
    }
    v_server->buffer = new_packet_buffer(v_server->socket_descriptor);
    v_server->socket_watcher.data = v_server;
    v_server->server = server;
    TAILQ_INSERT_TAIL(server->v_servers, v_server, v_server);

    free(address);
    return true;
}

struct packet_buffer* new_packet_buffer(int fd)
{
    struct packet_buffer* packet_buf;
    unsigned num_packets;
    socklen_t opt_len;
    int receive_size;

    opt_len = sizeof(receive_size);
    if (0 != getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*)&receive_size, &opt_len)) {
        Log("getsockopt failed: %s", strerror(errno));
        return NULL;
    }

    num_packets = (unsigned)receive_size / 1370;
    Log("packet buffer size: %d bytes; packet amount set to %u",
        receive_size, num_packets);
    receive_size += MAX_PACKET_SIZE;

    packet_buf = calloc(1, sizeof(*packet_buf));
    packet_buf->buffer_data = malloc(receive_size);
    packet_buf->cmsg_data = malloc(num_packets * CMSG_SIZE);
    packet_buf->vecs = malloc(num_packets * sizeof(packet_buf->vecs[0]));
    packet_buf->local_addresses = malloc(num_packets * sizeof(packet_buf->local_addresses[0]));
    packet_buf->peer_addresses = malloc(num_packets * sizeof(packet_buf->peer_addresses[0]));
    packet_buf->buffer_size = receive_size;
    packet_buf->packet_amount = num_packets;
    packet_buf->ecn = malloc(num_packets * sizeof(packet_buf->ecn[0]));

    for (int n = 0; n < num_packets; ++n) {
        packet_buf->vecs[n].iov_base = packet_buf->buffer_data + MAX_PACKET_SIZE * n;
        packet_buf->vecs[n].iov_len = MAX_PACKET_SIZE;
        packet_buf->packets[n] = (struct msghdr) {
            .msg_name = &packet_buf->peer_addresses[n],
            .msg_namelen = sizeof(packet_buf->peer_addresses[n]),
            .msg_iov = &packet_buf->vecs[n],
            .msg_iovlen = 1,
            .msg_control = packet_buf->cmsg_data + CMSG_SIZE * n,
            .msg_controllen = CMSG_SIZE,
        };
    }

    return packet_buf;
}

// open and configure the socket
bool v_server_configure_socket(struct v_server* v_server)
{
    int sockfd, saved_errno, s;
    int flags;
    int on = 1;
    socklen_t socklen;
    char addr_str[0x20];
    int sendbuf_val, rcvbuf_val;
    char* rcvbuf = getenv("RECVBUF_SIZE");
    char* sendbuf = getenv("SENDBUF_SIZE");
    const struct sockaddr* sa_local = (struct sockaddr*)&v_server->sas;

    switch (sa_local->sa_family) {
    case AF_INET:
        socklen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        socklen = sizeof(struct sockaddr_in6);
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    sockfd = socket(sa_local->sa_family, SOCK_DGRAM, 0);
    if (-1 == sockfd)
        return false;

    if (AF_INET6 == sa_local->sa_family
        && setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
               &on, sizeof(on))
            == -1) {
        close(sockfd);
        return false;
    }

    if (0 != bind(sockfd, sa_local, socklen)) {
        saved_errno = errno;
        Log("bind failed: %s", strerror(errno));
        close(sockfd);
        errno = saved_errno;
        return false;
    }

    /* Make socket non-blocking */
    flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return false;
    }
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return false;
    }

    on = 1;
    if (AF_INET == sa_local->sa_family)
        s = setsockopt(sockfd, IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
    else {
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    }

    if (0 != s) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return false;
    }

    on = 1;
    s = setsockopt(sockfd, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on));
    if (0 != s) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return false;
    }

    if (AF_INET == sa_local->sa_family) {
        on = IP_PMTUDISC_PROBE;
        s = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &on,
            sizeof(on));
        if (0 != s) {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return false;
        }
    } else if (AF_INET6 == sa_local->sa_family) {
        int on = IP_PMTUDISC_PROBE;
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on));
    }

    on = 1;
    if (AF_INET == sa_local->sa_family) {
        s = setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS,
            &on, sizeof(on));
        if (!s)
            s = setsockopt(sockfd, IPPROTO_IP, IP_TOS,
                &on, sizeof(on));
    } else {
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS,
            &on, sizeof(on));
        if (!s)
            s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS,
                &on, sizeof(on));
    }
    if (0 != s) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }
    Log("server ECN support is enabled.");

    if (sendbuf != NULL && (sendbuf_val = atoi(sendbuf))) {
        s = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuf_val,
            sizeof(sendbuf_val));
        if (0 != s) {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (rcvbuf != NULL && (rcvbuf_val = atoi(rcvbuf))) {
        s = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_val,
            sizeof(rcvbuf_val));
        if (0 != s) {
            saved_errno = errno;
            close(sockfd);
            errno = saved_errno;
            return -1;
        }
    }

    if (0 != getsockname(sockfd, (struct sockaddr*)sa_local, &socklen)) {
        saved_errno = errno;
        close(sockfd);
        errno = saved_errno;
        return -1;
    }

    memcpy((void*)&v_server->local_address, sa_local,
        sa_local->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    switch (sa_local->sa_family) {
    case AF_INET:
        Log("local address: %s:%d",
            inet_ntop(AF_INET, &((struct sockaddr_in*)sa_local)->sin_addr,
                addr_str, sizeof(addr_str)),
            ntohs(((struct sockaddr_in*)sa_local)->sin_port));
        break;
    }

    v_server->socket_descriptor = sockfd;

    return true;
}

/* connection methods */

void serverListen(Server* server)
{
    ev_run(server->event_loop, 0);
    ev_timer_stop(server->event_loop, &server->time_watcher);
    ev_loop_destroy(server->event_loop);
    lsquic_engine_destroy(server->quic_engine);
    lsquic_global_cleanup();
    free(server->keylog_path);
}

static int server_packets_out(void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count)
{
    struct v_server* v_server = packets_out_ctx;
    int fd, response = 0;
    struct mmsghdr messages[MAX_OUT_BATCH_SIZE];
    enum cmsg_opts opts;
    union {
        /* cmsg(3) recommends union for proper alignment */
        unsigned char buf[CMSG_SPACE(MAX(sizeof(struct in_pktinfo),
                              sizeof(struct in6_pktinfo)))
            + CMSG_SPACE(sizeof(int))];
        struct cmsghdr cmsg;
    } ancillary[MAX_OUT_BATCH_SIZE];

    if (0 == count)
        return 0;

    for (int i = 0; i < count && i < MAX_OUT_BATCH_SIZE; i++) {
        messages[i].msg_hdr.msg_flags = 0;
        unsigned n = 0;
        fd = (int)(uint64_t)specs[n].peer_ctx;
        messages[i].msg_hdr.msg_name = (void*)specs[n].dest_sa;
        messages[i].msg_hdr.msg_namelen = (AF_INET == specs[n].dest_sa->sa_family
                ? sizeof(struct sockaddr_in)
                : sizeof(struct sockaddr_in6)),
        messages[i].msg_hdr.msg_iov = specs[n].iov;
        messages[i].msg_hdr.msg_iovlen = specs[n].iovlen;

        opts = SEND_ADDR;
        if (specs[n].ecn)
            opts |= SEND_ECN;
        if (opts)
            format_control_message(&messages[i].msg_hdr, opts, &specs[n], ancillary[i].buf,
                sizeof(ancillary[i].buf));
        else {
            messages[i].msg_hdr.msg_control = NULL;
            messages[i].msg_hdr.msg_controllen = 0;
        }
    }

    response = sendmmsg(fd, messages, count, 0);
    if (response < (int)count) {
        handle_send_failure(v_server->server, fd);
        if (response < 0) {
            Log("sendmsg failed: %s", strerror(errno));
        } else if (response > 0) {
            errno = EAGAIN;
        }
    }
    return response;
}

void handle_send_failure(Server* server, int fd)
{
    ev_io* ev_schedular = calloc(1, sizeof(ev_io));
    ev_schedular->data = server->quic_engine;
    ev_io_init(ev_schedular, schedule_resend, fd, EV_WRITE);
    ev_io_start(server->event_loop, ev_schedular);
}

void schedule_resend(EV_P_ ev_io* ev_write, int revents)
{
    Server* server = ev_write->data;
    lsquic_engine_t* engine = server->quic_engine;
    ev_io_stop(server->event_loop, ev_write);
    free(ev_write);
    lsquic_engine_send_unsent_packets(engine);
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
