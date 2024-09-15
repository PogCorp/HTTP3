#include <errno.h>
#include <stdlib.h>

#include "logger.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "server.h"

struct lsquic_stream_ctx {
    // total size of payload
    size_t rcv_total_size;
    // offset of written/read payload
    off_t rcv_offset;
    // payload data
    char* rcv_buffer;
    // used in conjunction to memstream to accumulate client data
    FILE* file_handler;

    size_t snd_total_size;
    off_t snd_offset;
    char* snd_buffer;

    lsquic_stream_t* stream;
    Server* server;
};

/* LSQUIC Callbacks */

/*
 * Callback to process the event of a new connection to the server
 * */
lsquic_conn_ctx_t* server_on_new_connection(
    void* stream_if_ctx,
    struct lsquic_conn* conn);

/*
 * Callback to process the event of a closed connection to the server
 * */
void server_on_closed_connection(lsquic_conn_t* conn);

lsquic_stream_ctx_t* server_on_new_stream(
    void* stream_if_ctx,
    struct lsquic_stream* stream);

void server_on_read(
    struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

void server_on_write(
    struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

void server_on_close(
    struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

static const struct lsquic_stream_if stream_interface = {
    .on_new_conn = server_on_new_connection,
    .on_conn_closed = server_on_closed_connection,
    .on_new_stream = server_on_new_stream,
    .on_read = server_on_read,
    .on_write = server_on_write,
    .on_close = server_on_close,
};

int main(int _, char* argv[])
{
    Server server;
    bool ok;
    char* alpn[] = {
        "echo",
    };

    char* certfile = getenv("CERTFILE");
    char* keyfile = getenv("KEYFILE");
    set_logger_fd(stdout);
    if (!certfile || !keyfile) {
        Log("failed to load cerfile or keyfile\n(cerfile,keyfile)=(%s,%s)\n", certfile, keyfile);
        return EXIT_FAILURE;
    }

    ok = new_server(&server, "./keylog", &stream_interface, &server);
    if (!ok) {
        Log("failure while creating new_server");
        return EXIT_FAILURE;
    }

    for (unsigned long i = 0; i < sizeof(alpn) / sizeof(alpn[0]); i++) {
        server_add_alpn(&server, alpn[i]);
    }

    ok = add_v_server(&server, "localhost:8080", certfile, keyfile);
    if (!ok) {
        Log("failed to add_v_server");
        return EXIT_FAILURE;
    }
    ok = server_listen(&server);
    if (!ok) {
        Log("error occured while initializing server");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/* stream methods */

void print_conn_info(const lsquic_conn_t* conn)
{
    const char* cipher;

    cipher = lsquic_conn_crypto_cipher(conn);

    Log("Connection info: version: %u; cipher: %s; key size: %d, alg key size: %d",
        lsquic_conn_quic_version(conn),
        cipher ? cipher : "<null>",
        lsquic_conn_crypto_keysize(conn),
        lsquic_conn_crypto_alg_keysize(conn));
}

lsquic_conn_ctx_t* server_on_new_connection(
    void* stream_if_ctx,
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

lsquic_stream_ctx_t* server_on_new_stream(
    void* stream_if_ctx,
    struct lsquic_stream* stream)
{
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("New Stream with id: %d", id);
    lsquic_stream_ctx_t* stream_ctx = calloc(1, sizeof(*stream_ctx));
    stream_ctx->stream = stream;
    stream_ctx->server = stream_if_ctx;
    stream_ctx->file_handler = open_memstream(&stream_ctx->rcv_buffer, &stream_ctx->rcv_total_size);
    if (stream_ctx->file_handler == NULL) {
        Log("failed to opem memstream");
        free(stream_ctx);
        return NULL;
    }
    lsquic_stream_wantread(stream, true);
    return stream_ctx;
}

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* stream_ctx)
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

    fwrite(buf, 1, num_read, stream_data->file_handler);
    fflush(stream_data->file_handler);
    Log("read %ld bytes", num_read);
    Log("read: '%.*s'", num_read, stream_data->rcv_buffer);
    stream_data->snd_total_size = stream_data->rcv_total_size;
    stream_data->snd_buffer = stream_data->rcv_buffer;
    lsquic_stream_wantread(stream, false);
    lsquic_stream_wantwrite(stream, true);
    // TODO: callback to treat data
    // lsquic_stream_wantwrite(stream, 1);
    // TODO: write back when it is not a final response
    return;
}

// TODO: this is only an echo test, change later
void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* stream_ctx)
{
    ssize_t num_written;
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    num_written = lsquic_stream_write(stream, stream_ctx->snd_buffer, stream_ctx->snd_total_size);
    lsquic_stream_flush(stream);
    if (num_written < 0) {
        Log("lsquic_stream_write() returned %ld, abort connection", (long)num_written);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    stream_ctx->snd_offset += num_written;
    if (num_written >= 0 && stream_ctx->snd_offset == stream_ctx->snd_total_size) {
        Log("All data was written back, stopping stream");
    }
}

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* stream_ctx)
{
    lsquic_stream_id_t id = lsquic_stream_id(stream);
    Log("%s called, closing stream %u", __func__, id);
    free(stream_ctx->rcv_buffer); // TODO: not freeing snd_buffer because is echoing, change later
    free(stream_ctx);
}
