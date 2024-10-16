#include "openssl/base.h"
#include <ev.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <lsquic.h>
#include <lsquic_hash.h>

#pragma once

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MAX_OUT_BATCH_SIZE 1024 // DOCS: max size of lsquic out packets. Defined in  https://lsquic.readthedocs.io/en/latest/internals.html#out-batch
#define MAX_PACKET_SIZE 65535
#define NDROPPED_SIZE CMSG_SPACE(sizeof(uint32_t)) // get a platform independent size of ancillary field for dropped packets
#define ECN_SIZE CMSG_SPACE(sizeof(int)) // get a platform independent size of ancillary field for ECN value
#define IPV4_DST_MSG_SIZE sizeof(struct sockaddr_in) // size of ipv4 field contained in ancillary packets
#define IPV6_DST_MSG_SIZE sizeof(struct in6_pktinfo) // size of ipv6 field contained in ancillary packets
// total size for ancillary. (just the sum of the previous)
#define CMSG_SIZE (CMSG_SPACE(MAX(IPV4_DST_MSG_SIZE, IPV6_DST_MSG_SIZE) + NDROPPED_SIZE + ECN_SIZE))

#define ALPN_LEN 0x100

enum ReadStatus {
    OK,
    NO_ROOM,
    ERROR,
};

enum IpVersion { IPV4,
    IPV6 };

struct v_server;
struct packet_buffer;

TAILQ_HEAD(v_servers, v_server);

typedef struct server {
    ev_timer time_watcher;
    struct ev_loop* event_loop;
    struct ssl_ctx_st* ssl_ctx;
    lsquic_engine_t* quic_engine;
    struct lsquic_engine_settings quic_settings;
    char alpn[ALPN_LEN];
    struct lsquic_hash* certificates;
    struct v_servers v_servers;
    struct lsquic_engine_api engine_api;
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
    uint32_t dropped_packets;
};

struct packet_buffer {
    unsigned char* buffer_data;
    unsigned char* cmsg_data;
    struct mmsghdr* packets;
    struct sockaddr_storage* local_addresses;
    struct sockaddr_storage* peer_addresses;
    struct iovec* vecs;
    int* ecn;
    unsigned packet_amount;
    unsigned buffer_size;
};

/*
 * Creates a new server for the provided parameters
 *
 * consumer must check errno to ensure that the configuration was appropriate
 * and server can listen
 * */
bool new_server(
    Server* server,
    const char* keylog,
    const struct lsquic_stream_if* stream_if,
    void* stream_if_ctx);

void server_add_alpn(Server* server, char* const proto);

void server_cleanup(Server* server);

bool server_prepare(Server* server);

bool server_listen(Server* server);

/*
 *
 * */
bool add_v_server(
    Server* server,
    const char* uri,
    const char* certkey,
    const char* keyfile);

struct packet_buffer* new_packet_buffer(int fd);

void packet_buffer_cleanup(struct packet_buffer* buffer);

bool v_server_configure_socket(struct v_server* v_server);

/* Connection methods */
int server_write_socket(
    void* packets_out_ctx,
    const struct lsquic_out_spec* specs,
    unsigned count);

void server_read_socket(EV_P_ ev_io* w, int revents);
