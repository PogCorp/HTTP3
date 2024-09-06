#include "openssl/base.h"
#include <ev.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <lsquic.h>
#include <lsquic_hash.h>

#pragma once

enum ReadStatus {
    OK,
    NO_ROOM,
    ERROR,
};

enum IpVersion {
    IPV4,
    IPV6
};

struct v_server;
struct packet_buffer;

TAILQ_HEAD(v_servers, v_server);

// TODO: write an interface type to comunicate with Go
typedef struct server {
    ev_timer time_watcher;
    struct ev_loop* event_loop;
    struct sockaddr_storage local_address;
    struct lsquic_stream_if stream_callbacks;
    struct lsquic_engine_settings settings;
    SSL_CTX* ssl_ctx;
    lsquic_engine_t* quic_engine;
    char* keylog_path;
    char alpn[0x100];
    struct lsquic_hash* certificates;
    struct v_servers* v_servers;
    // interface QuicAdapter adapter_callbacks;
} Server;

struct v_server {
    TAILQ_ENTRY(v_server)
    v_server;
    int socket_descriptor;
    struct sockaddr_storage sas;
    struct sockaddr_storage local_addr;
    char* sni;
    Server* server;
    enum IpVersion ip_ver;
    struct packet_buffer* buffer;
    ev_io socket_watcher;
};

struct packet_buffer {
    unsigned char* buffer_data;
    unsigned char* cmsg_data;
    struct iovec* iovecs;
    struct sockaddr_storage *local_addr,
        *peer_addr;
    unsigned n_alloc;
    unsigned buffer_size;
};

typedef struct {
    // total size of payload
    size_t total_size;
    // offset of written/read payload
    off_t offset;
    // payload data
    unsigned char* buffer;
} server_stream_ctx;

/* TODO: add Cgo callbacks */

/*
 * Creates a new server for the provided parameters
 *
 * consumer must check errno to ensure that the configuration was appropriate
 * and server can listen
 * */
void newServer(Server* server, const char* keylog);

/*
 *
 * */
bool add_v_server(Server* server, const char* uri,
    const char* certkey, const char* keyfile);

void read_socket(EV_P_ ev_io* w, int revents);

/* connection methods */
static int server_packets_out(void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count);

/* LSQUIC Callbacks */

/*
 * Callback to process the event of a new connection to the server
 * */
lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn);

/*
 * Callback to process the event of a closed connection to the server
 * */
void server_on_closed_connection(lsquic_conn_t* conn);

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx,
    struct lsquic_stream* stream);

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);

void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);
