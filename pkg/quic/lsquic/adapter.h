#include "lsquic.h"
#include "server.h"

struct lsquic_conn_ctx {
    void* adapter_ctx;
};

struct lsquic_stream_ctx {
    char* send_buffer;
    size_t send_buffer_size;
    off_t send_buffer_off;
    void* adapter_ctx;
};

/**/

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

void server_on_read(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

void server_on_write(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

void server_on_close(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

bool lsquic_new_server(
    Server* server,
    const char* keylog,
    void* stream_if_ctx);
