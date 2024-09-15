#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "logger.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_util.h"

struct lsquic_conn_ctx {
    void* adapter_ctx;
};

struct lsquic_stream_ctx {
    char* send_buffer;
    size_t send_buffer_size;
    void* adapter_ctx;
};

/* Adapter Callbacks */
extern lsquic_stream_ctx_t* adapterOnNewConnection(lsquic_conn_t* conn, void* stream_if_ctx);
extern void adapterOnClosedConnection(lsquic_conn_t* conn);
extern void adapterOnNewStream(lsquic_stream_t* stream, void* adapter_ctx);
extern void adapterOnRead(lsquic_stream_t* stream, char* buf, size_t buf_size,
    void* adapter_ctx);
extern void adapterOnClose(lsquic_stream_t* stream, void* adapter_ctx);

/**/

/* LSQUIC Callbacks */

/*
 * Callback to process the event of a new connection to the server
 * */
extern lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn);

/*
 * Callback to process the event of a closed connection to the server
 * */
extern void server_on_closed_connection(lsquic_conn_t* conn);

extern lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx,
    struct lsquic_stream* stream);

extern void server_on_read(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

extern void server_on_write(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

extern void server_on_close(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

static const struct lsquic_stream_if stream_interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

/* stream methods */

void print_conn_info(const lsquic_conn_t* conn)
{
    const char* cipher;

    cipher = lsquic_conn_crypto_cipher(conn);

    Log("Connection info: version: %u; cipher: %s; key size: %d, alg key size: "
        "%d",
        lsquic_conn_quic_version(conn), cipher ? cipher : "<null>",
        lsquic_conn_crypto_keysize(conn), lsquic_conn_crypto_alg_keysize(conn));
}

lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn)
{
    const lsquic_cid_t* cid = lsquic_conn_id(conn);
    char cid_string[0x29];
    lsquic_hexstr(cid->idbuf, cid->len, cid_string, sizeof(cid_string));
    const char* sni = lsquic_conn_get_sni(conn);
    Log("new connection %s, for sni: %s", cid_string, sni ? sni : "not set");
    print_conn_info(conn);
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
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("New Stream with id: %d", id);
    lsquic_stream_ctx_t* stream_ctx = calloc(1, sizeof(*stream_ctx));
    lsquic_stream_wantread(stream, true);
    return stream_ctx;
}

void server_on_read(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    struct lsquic_stream_ctx* const stream_data = (void*)stream_ctx;
    ssize_t num_read;
    unsigned char buf[0x400];

    if (stream_ctx == NULL) {
        Log("in %s: received NULL context", __func__);
        lsquic_stream_close(stream);
        return;
    }

    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("Trying to read from Stream with id: %d", id);
    num_read = lsquic_stream_read(stream, buf, sizeof(buf));

    if (num_read < 0) {
        /* This should not happen */
        Log("error reading from stream (errno: %d) -- abort connection", errno);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }

    Log("read %ld bytes", num_read);
    lsquic_stream_wantread(stream, false);
    lsquic_stream_wantwrite(stream, true);
    // TODO: callback to treat data
    // lsquic_stream_wantwrite(stream, 1);
    return;
}

void server_on_write(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    ssize_t num_written;
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    unsigned char buf[0x400];
    num_written = lsquic_stream_write(stream, buf, sizeof(buf));
    lsquic_stream_flush(stream);
    if (num_written < 0) {
        Log("lsquic_stream_write() returned %ld, abort connection",
            (long)num_written);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    Log("All data was written back, stopping stream");
}

void server_on_close(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx)
{
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("%s called, closing stream %u", __func__, id);
    free(stream_ctx);
}
