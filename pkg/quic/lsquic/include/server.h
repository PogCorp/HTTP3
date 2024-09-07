#include "openssl/base.h"
#include <ev.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <lsquic.h>
#include <lsquic_hash.h>

#pragma once

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MAX_OUT_BATCH_SIZE 1024
#define MAX_OUT_BATCH_SIZE 1024 // DOCS: max size of lsquic out packets. Defined in  https://lsquic.readthedocs.io/en/latest/internals.html#out-batch
#define MAX_PACKET_SIZE 65535
#define NDROPPED_SIZE CMSG_SPACE(sizeof(uint32_t)) // get a platform independent size of ancillary field for dropped packets
#define ECN_SIZE CMSG_SPACE(sizeof(int)) // get a platform independent size of ancillary field for ECN value
#define IPV4_DST_MSG_SIZE sizeof(struct sockaddr_in) // size of ipv4 field contained in ancillary packets
#define IPV6_DST_MSG_SIZE sizeof(struct sockaddr_in) // size of ipv6 field contained in ancillary packets
// total size for ancillary. (just the sum of the previous)
#define CMSG_SIZE (CMSG_SPACE(MAX(IPV4_DST_MSG_SIZE, IPV6_DST_MSG_SIZE) + NDROPPED_SIZE + ECN_SIZE))

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
    struct sockaddr_storage local_address;
    Server* server;
    enum IpVersion ip_ver;
    struct packet_buffer* buffer;
    ev_io socket_watcher;
};

struct packet_buffer {
    unsigned char* buffer_data;
    unsigned char* cmsg_data;
    struct msghdr* packets;
    struct sockaddr_storage* local_addresses;
    struct sockaddr_storage* peer_addresses;
    struct iovec* vecs;
    int* ecn;
    unsigned packet_amount;
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

struct packet_buffer* new_packet_buffer(int fd);

bool v_server_configure_socket(struct v_server* v_server);

void server_read_socket(EV_P_ ev_io* w, int revents);

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
