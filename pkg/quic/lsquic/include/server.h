#include "engine.h"
#include <ev.h>
#include <lsquic.h>
#include <sys/socket.h>
#pragma once

typedef struct server {
    int socket_descriptor;
    ev_io socket_watcher;
    ev_timer time_watcher;
    struct ev_loop* event_loop;
    struct sockaddr_storage local_address;
    struct lsquic_stream_if stream_callbacks;
    LsquicEngine* engine;
} Server;

typedef struct {
    // total size of payload
    size_t total_size;
    // offset of written/read payload
    off_t offset;
    // payload data
    unsigned char* buffer;
} server_stream_ctx;

/*
 * Creates a new server and attaches it to the engine
 * */
void newServer(Server* server, const char* host_name, char* port, const char* certkeym, const char* keyfile, LsquicEngine* engine);

/*
 * Callback to process the event of a new connection to the server
 * */
lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx, struct lsquic_conn* conn);

/*
 * Callback to process the event of a closed connection to the server
 * */
void server_on_closed_connection(lsquic_conn_t* conn);

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx, struct lsquic_stream* stream);

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);

void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* h);
