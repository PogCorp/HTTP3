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
#include "logger.h"
#include "lsquic.h"
#include "lsquic_hash.h"
#include "server.h"

/* process ticker */
void reset_timer(EV_P_ ev_timer* timer, int revents);
void process_ticker(Server* server);

/* ssl configuration */
static SSL_CTX* server_get_ssl_ctx(
    void* peer_ctx,
    const struct sockaddr* address);

bool set_ssl_ctx(Server* server);

/* add ALPN value */
static bool add_alpn(char* alpn, char* proto);

/* handlers for send failure */
void handle_send_failure(Server* server, int fd);
void schedule_resend(EV_P_ ev_io* ev_write, int revents);

// TODO: write a helper function to format sni from hostname, port, certkey,
// keyfile
//
//
// TODO: certify that the get_address_info function works correctly since it
// expects ip
//      address instead of a https scheme, therefore there might be a need to
//      resolve the ip

// NOTE: There should be a wrapper func to GO here
bool new_server(
    Server* server,
    const char* keylog,
    const struct lsquic_stream_if* stream_if,
    void* stream_if_ctx)
{
    // initialize every field with default 0
    memset(server, 0, sizeof(Server));
    server->event_loop = EV_DEFAULT;
    TAILQ_INIT(&server->v_servers);

    // registering callbacks and starting engine
    lsquic_engine_init_settings(&server->quic_settings, LSENG_SERVER);
    server->quic_settings.es_versions = 1 << LSQVER_I001; // default to version 1 of QUIC
    server->quic_settings.es_ecn = LSQUIC_DF_ECN;
    server->quic_settings.es_rw_once = true; // eases the span of on_read callback

    server->engine_api.ea_packets_out = server_write_socket;
    server->engine_api.ea_packets_out_ctx = server;
    server->engine_api.ea_get_ssl_ctx = server_get_ssl_ctx;
    server->engine_api.ea_stream_if = stream_if;
    server->engine_api.ea_stream_if_ctx = stream_if_ctx;
    server->engine_api.ea_settings = &server->quic_settings;

    /* certificates */
    server->certificates = lsquic_hash_create();
    server->engine_api.ea_lookup_cert = lookup_cert_callback;
    server->engine_api.ea_cert_lu_ctx = server->certificates;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        Log("Failed to initialize global context for LSQUIC");
        return false;
    }

    setup_keylog_dir(keylog);

    server->quic_engine = lsquic_engine_new(LSENG_SERVER, &server->engine_api);
    if (server->quic_engine == NULL) {
        // TODO: select a more appropriate errno value here
        errno = ENOPROTOOPT;
        Log("engine could not be created");
        return false;
    }

    return true;
}

void server_add_alpn(Server* server, char* const proto)
{
    add_alpn(server->alpn, proto);
    int ver = lsquic_str2ver(proto, strlen(proto));
    if (ver >= 0) {
        server->quic_settings.es_versions = 1 << ver;
    }
}

// cleanup all virtual servers and event loop
void server_cleanup(Server* server)
{
    struct v_server* e = NULL;
    TAILQ_FOREACH(e, &server->v_servers, v_server)
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
    SSL_CTX_free(server->ssl_ctx);
    clean_certificates(server->certificates);
    lsquic_engine_destroy(server->quic_engine);
    lsquic_global_cleanup();
}

bool server_listen(Server* server)
{
    bool ok = server_prepare(server);
    if (!ok) {
        Log("failed to prepare server in %s", __func__);
        server_cleanup(server);
        return false;
    }

    ok = set_ssl_ctx(server);
    if (!ok) {
        Log("failed to set ssl ctx");
        return false;
    }

    server->quic_engine = lsquic_engine_new(LSENG_SERVER, &server->engine_api);
    if (server->quic_engine == NULL) {
        // TODO: select a more appropriate errno value here
        errno = ENOPROTOOPT;
        Log("engine could not be created");
        return false;
    }

    server->time_watcher.data = server;
    ev_timer_init(&server->time_watcher, reset_timer, 0, 0);
    ev_timer_start(server->event_loop, &server->time_watcher);

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
    ok = v_server_set_address_info(v_server, host, port);
    if (!ok) {
        Log("failed to bind socket for %s", uri);
        return false;
    }
    ok = v_server_configure_socket(v_server);
    if (!ok) {
        Log("failed to configure socket for %s", uri);
        free(v_server);
        return false;
    }
    v_server->buffer = new_packet_buffer(v_server->socket_descriptor);
    v_server->socket_watcher.data = v_server;
    v_server->server = server;
    TAILQ_INSERT_TAIL(&server->v_servers, v_server, v_server);

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
    packet_buf->buffer_size = receive_size;
    packet_buf->packet_amount = num_packets;
    packet_buf->buffer_data = malloc(receive_size);
    packet_buf->cmsg_data = malloc(num_packets * CMSG_SIZE);
    packet_buf->vecs = malloc(num_packets * sizeof(packet_buf->vecs[0]));
    packet_buf->local_addresses = malloc(num_packets * sizeof(packet_buf->local_addresses[0]));
    packet_buf->peer_addresses = malloc(num_packets * sizeof(packet_buf->peer_addresses[0]));
    packet_buf->ecn = malloc(num_packets * sizeof(packet_buf->ecn[0]));
    packet_buf->packets = malloc(num_packets * sizeof(packet_buf->packets[0]));

    return packet_buf;
}

void packet_buffer_cleanup(struct packet_buffer* buffer)
{
    free(buffer->vecs);
    free(buffer->local_addresses);
    free(buffer->peer_addresses);
    free(buffer->ecn);
    free(buffer->cmsg_data);
    free(buffer->buffer_data);
    free(buffer);
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
        int opt = IP_PMTUDISC_PROBE;
        s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &opt, sizeof(opt));
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
    case AF_INET6:
        break;
    default:
        Log("invalid sa_family while configuring socket");
        return false;
    }

    v_server->socket_descriptor = sockfd;

    return true;
}

/* connection methods */

int server_write_socket(
    void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count)
{
    Server* server = packets_out_ctx;
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

    // FIXME: peer_ctx should pass the file descripto as well. Add struct containing ssl ctx and fd
    // fd = *(int*)specs->peer_ctx;
    fd = TAILQ_FIRST(&server->v_servers)->socket_descriptor;

    for (unsigned int i = 0; i < count && i < MAX_OUT_BATCH_SIZE; i++) {
        messages[i].msg_hdr.msg_flags = 0;
        messages[i].msg_hdr.msg_name = (void*)specs[i].dest_sa;
        messages[i].msg_hdr.msg_namelen = (AF_INET == specs[i].dest_sa->sa_family
                ? sizeof(struct sockaddr_in)
                : sizeof(struct sockaddr_in6)),
        messages[i].msg_hdr.msg_iov = specs[i].iov;
        messages[i].msg_hdr.msg_iovlen = specs[i].iovlen;

        opts = SEND_ADDR;
        if (specs[i].ecn)
            opts |= SEND_ECN;
        if (opts)
            format_control_message(&messages[i].msg_hdr, opts, &specs[i], ancillary[i].buf,
                sizeof(ancillary[i].buf));
        else {
            messages[i].msg_hdr.msg_control = NULL;
            messages[i].msg_hdr.msg_controllen = 0;
        }
    }

    response = sendmmsg(fd, messages, count, 0);
    if (response < (int)count) {
        handle_send_failure(server, fd);
        if (response < 0) {
            Log("sendmsg failed: %s", strerror(errno));
        } else if (response > 0) {
            errno = EAGAIN;
        }
    }
    return response;
}

// TODO:  whenever the amount of packets read coincides with the value of packets_amount,
//       this function will be called again for no reason, therefore look for a more
//       logical way to identify that there are still packets that could no be read
enum ReadStatus receive_packets(struct v_server* v_server, unsigned int* packets_read)
{
    struct packet_buffer* buffer = v_server->buffer;
    struct sockaddr_storage* local_address;
    uint32_t dropped_packets;
    int response;
    int i;

    for (unsigned int n = 0; n < buffer->packet_amount; ++n) {
        buffer->vecs[n].iov_base = buffer->buffer_data + MAX_PACKET_SIZE * n;
        buffer->vecs[n].iov_len = MAX_PACKET_SIZE;
        buffer->packets[n].msg_hdr.msg_name = &buffer->peer_addresses[n];
        buffer->packets[n].msg_hdr.msg_namelen = sizeof(buffer->peer_addresses[n]);
        buffer->packets[n].msg_hdr.msg_iov = &buffer->vecs[n];
        buffer->packets[n].msg_hdr.msg_iovlen = 1,
        buffer->packets[n].msg_hdr.msg_control = buffer->cmsg_data + CMSG_SIZE * n;
        buffer->packets[n].msg_hdr.msg_controllen = CMSG_SIZE;
    }

    response = recvmmsg(v_server->socket_descriptor, buffer->packets, buffer->packet_amount, 0, NULL);
    if (response < 0) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            Log("error in recvmmsg, got err: %s", strerror(errno));
        return ERROR;
    }

    for (i = 0; i < response; i++) {
        local_address = &buffer->local_addresses[i];
        memcpy(local_address, &v_server->local_address, sizeof(*local_address));
        dropped_packets = 0;
        buffer->ecn[i] = 0;
        read_control_message(&buffer->packets[i].msg_hdr, local_address, &dropped_packets, &buffer->ecn[i]);
        v_server->dropped_packets = dropped_packets;
        buffer->vecs[i].iov_len = buffer->packets[i].msg_len;
    }
    *packets_read = i;
    return i == buffer->packet_amount ? NO_ROOM : OK;
}

void server_read_socket(EV_P_ ev_io* w, int revents)
{
    enum ReadStatus status;
    unsigned int i, read_packets = 0, batches = 0;
    struct v_server* v_server = w->data;
    struct packet_buffer* buffer = v_server->buffer;
    lsquic_engine_t* engine = v_server->server->quic_engine;

    do {
        status = receive_packets(v_server, &read_packets);
        batches += read_packets > 0;
        for (i = 0; i < read_packets; i++) {
            if (0 > lsquic_engine_packet_in(
                    engine,
                    buffer->vecs[i].iov_base,
                    buffer->vecs[i].iov_len,
                    (struct sockaddr*)&buffer->local_addresses[i],
                    (struct sockaddr*)&buffer->peer_addresses[i],
                    v_server->server->ssl_ctx,
                    buffer->ecn[i])) {
                Log("ERROR! lsquic_engine_in did not process packets");
                break;
            }
        }
        if (i > 0) {
            process_ticker(v_server->server);
        }
    } while (status == NO_ROOM);
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
    const struct sockaddr* _)
{
    SSL_CTX* ssl_ctx = (SSL_CTX*)peer_ctx;
    return ssl_ctx;
}

bool set_ssl_ctx(Server* server)
{
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
    return true;
}

void process_ticker(Server* server)
{
    int time_diff;
    ev_tstamp timeout;

    ev_timer_stop(server->event_loop, &server->time_watcher);
    lsquic_engine_process_conns(server->quic_engine);

    if (lsquic_engine_earliest_adv_tick(server->quic_engine, &time_diff)) {
        if ((unsigned)time_diff >= server->quic_settings.es_clock_granularity)
            timeout = (ev_tstamp)time_diff / 1000000;
        else if (time_diff <= 0)
            timeout = 0.0;
        else
            timeout = (ev_tstamp)server->quic_settings.es_clock_granularity / 1000000;
        ev_timer_init(&server->time_watcher, reset_timer, timeout, 0.);
        ev_timer_start(server->event_loop, &server->time_watcher);
    }
}

void reset_timer(EV_P_ ev_timer* timer, int revents)
{
    process_ticker(timer->data);
}

bool server_prepare(Server* server)
{
    char errbuf[0x100];
    if (keylog_dir) {
        struct lsquic_hash_elem* elem = lsquic_hash_first(server->certificates);
        for (; elem; elem = lsquic_hash_next(server->certificates)) {
            struct certificateElem* data = lsquic_hashelem_getdata(elem);
            SSL_CTX_set_keylog_callback(data->ssl_ctx, keylog_log_line);
        }
    }

    if (TAILQ_EMPTY(&server->v_servers)) {
        Log("no virtual servers where configured");
        return false;
    }

    struct v_server* v = NULL;
    TAILQ_FOREACH(v, &server->v_servers, v_server)
    {
        ev_io_init(&v->socket_watcher, server_read_socket, v->socket_descriptor, EV_READ);
        ev_io_start(server->event_loop, &v->socket_watcher);
    }

    if (0 != lsquic_engine_check_settings(&server->quic_settings, LSENG_SERVER, errbuf, sizeof(errbuf))) {
        errno = EINVAL;
        Log("invalid settings passed: %s", errbuf);
        return false;
    }

    return true;
}
