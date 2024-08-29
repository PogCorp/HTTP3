#include "server.h"
#include "logger.c"
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

void reset_timer(EV_P_ ev_timer* timer, int revents);

void newServer(Server* server, const char* host_name, char* port, const char* certkeym, const char* keyfile, LsquicEngine* engine)
{
    union {
        struct sockaddr sa;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } address;

    const int port_num = htons(atoi(port));

    if (inet_pton(AF_INET, host_name, &address.addr4.sin_addr)) {
        address.addr4.sin_family = AF_INET;
        address.addr4.sin_port = port_num;
    } else if (memset(&address.addr6, 0, sizeof(address.addr6)),
        inet_pton(AF_INET6, host_name, &address.addr6.sin6_addr)) {
        address.addr6.sin6_family = AF_INET6;
        address.addr6.sin6_port = port_num;
    } else {
        log("'%s' is not a valid IP address", host_name);
        exit(EXIT_FAILURE);
    }
}

lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx, struct lsquic_conn* conn)
{
    return NULL;
}

void server_on_closed_connection(lsquic_conn_t* conn)
{
}

lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx, struct lsquic_stream* stream)
{
    return NULL;
}

void server_on_read(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void server_on_write(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void server_on_close(struct lsquic_stream* stream, lsquic_stream_ctx_t* h)
{
}

void process_ticker(Server* server)
{
    int time_diff;
    ev_tstamp timeout;

    ev_timer_stop(server->event_loop, &server->time_watcher);
    lsquic_engine_process_conns(server->engine->quic_engine);

    if (lsquic_engine_earliest_adv_tick(server->engine->quic_engine, &time_diff)) {
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
