#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "adapter.h"
#include "logger.h"
#include "server.h"

#ifndef ADAPTER
#define ADAPTER

extern lsquic_conn_ctx_t* adapterOnNewConnection(lsquic_conn_t* conn, void* stream_if_ctx);
extern void adapterOnClosedConnection(lsquic_conn_t* conn);
extern lsquic_stream_ctx_t* adapterOnNewStream(lsquic_stream_t* stream, void* stream_ctx);
extern void adapterOnRead(lsquic_stream_t* stream, char* buf, size_t buf_size, lsquic_stream_ctx_t* stream_ctx);
extern void adapterOnWrite(lsquic_stream_t* stream, lsquic_stream_ctx_t* stream_ctx);
extern void adapterOnClose(lsquic_stream_t* stream, lsquic_stream_ctx_t* stream_ctx);

/* Adapter Callbacks */

static const struct lsquic_stream_if stream_interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

bool lsquic_new_server(
    Server* server,
    const char* keylog,
    void* stream_if_ctx)
{
    return new_server(server, keylog, &stream_interface, stream_if_ctx);
}

/* stream methods */

lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn)
{
    const char* sni = lsquic_conn_get_sni(conn);
    Log("got new connection for sni: %s", sni ? sni : "not set");
    return adapterOnNewConnection(conn, stream_if_ctx);
}

void server_on_closed_connection(lsquic_conn_t* conn)
{
    adapterOnClosedConnection(conn);
}

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx,
    struct lsquic_stream* stream)
{
    lsquic_stream_ctx_t* stream_ctx = stream_if_ctx;
    return adapterOnNewStream(stream, stream_ctx->adapter_ctx);
}

void server_on_read(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    ssize_t num_read;
    char buf[0x400];
    adapterOnRead(stream, buf, sizeof(buf), stream_ctx);
    return;
}

void server_on_write(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    ssize_t num_written;
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("trying to write to stream with id: #%u", id);
    adapterOnWrite(stream, stream_ctx);
}

void server_on_close(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("%s called, closing stream %u", __func__, id);
    adapterOnClose(stream, stream_ctx);
}
#endif
