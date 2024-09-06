#include "logger.c"
#include "server.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

typedef union socketAddress {
    struct sockaddr sa;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
} SocketAddress;

static bool validate_uri(const char* uri)
{
    return false;
}

static bool get_address_info(struct v_server* server, const char* host, const char* port, SocketAddress* address)
{
    struct addrinfo hints, *res = NULL;
    int err, port_num;
    bool ok = false;

    port_num = atoi(port);

    if (inet_pton(AF_INET, host, &address->addr4.sin_addr)) {
        address->addr4.sin_family = AF_INET;
        address->addr4.sin_port = htons(port_num);
    } else if (memset(&address->addr6, 0, sizeof(address->addr6)),
        inet_pton(AF_INET6, host, &address->addr6.sin6_addr)) {
        address->addr6.sin6_family = AF_INET6;
        address->addr6.sin6_port = htons(port_num);
    } else {
        Log("passed on an valid IP address: '%s'", host);
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICSERV;
        if (server->ip_ver == IPV4)
            hints.ai_family = AF_INET;
        else if (server->ip_ver == IPV6)
            hints.ai_family = AF_INET6;
        err = getaddrinfo(host, port, &hints, &res);
        if (err != 0) {
            Log("could not resolve %s:%s: %s", host, port,
                gai_strerror(err));
            goto defer;
        }
        if (res->ai_addrlen > sizeof(server->sas)) {
            Log("resolved socket length is too long");
            goto defer;
        }
        memcpy(&server->sas, res->ai_addr, res->ai_addrlen);
        ok = true;
    }

defer:
    if (res)
        freeaddrinfo(res);
    return ok;
}
