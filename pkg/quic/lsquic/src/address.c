#include "logger.h"
#include "server.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

typedef union socketAddress {
    struct sockaddr sa;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
} SocketAddress;

#define CAPTURE_GROUPS 5 // this actually means 4 capture groups, since the first is the whole string to be captured

static bool validate_uri(char* uri, char** host, char** port_str)
{
    char errbuf[80];
    regex_t regex;
    regmatch_t matches[CAPTURE_GROUPS];
    int regex_code = regcomp(&regex, "^(.*):([0-9][0-9]*)$"
                                     "|^([0-9][0-9]*)$"
                                     "|^(..*)$",
        REG_EXTENDED);

    if (regex_code != 0) {
        regerror(regex_code, &regex, errbuf, sizeof(errbuf));
        Log("failed to compile regex, got err: %s", errbuf);
        return false;
    }

    char* address = uri;
    if (0 != regexec(&regex, address, CAPTURE_GROUPS, matches, 0)) {
        Log("Passed invalid argument: %s'", address);
        free(address);
        return false;
    }

    // here it is safe to point host and port_str to regions of address since it is on heap
    if (matches[1].rm_so >= 0) {
        // both host and port informed
        address[matches[1].rm_so + matches[1].rm_eo] = '\0';
        *host = address;
        *port_str = &address[matches[2].rm_so];
    } else if (matches[3].rm_so >= 0) {
        // host not informed, defaulting to localhost
        *host = "localhost";
        *port_str = &address[matches[3].rm_so];
    } else {
        // port not informed, defaulting to 443 (HTTPS default)
        assert(matches[4].rm_so >= 0);
        *host = address;
        *port_str = "443";
    }

    if (0 == regex_code)
        regfree(&regex);

    return true;
}

static bool v_server_set_address_info(
    struct v_server* server,
    const char* host,
    const char* port)
{
    struct addrinfo hints, *res = NULL;
    int err, port_num;
    bool ok = false;
    SocketAddress* address = (SocketAddress*)&server->sas;

    port_num = atoi(port);

    if (inet_pton(AF_INET, host, &address->addr4.sin_addr)) {
        address->addr4.sin_family = AF_INET;
        address->addr4.sin_port = htons(port_num);
        server->ip_ver = IPV4;
    } else if (memset(&address->addr6, 0, sizeof(address->addr6)),
        inet_pton(AF_INET6, host, &address->addr6.sin6_addr)) {
        address->addr6.sin6_family = AF_INET6;
        address->addr6.sin6_port = htons(port_num);
        server->ip_ver = IPV6;
    } else {
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICSERV;
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
        if (res->ai_family == AF_INET)
            server->ip_ver = IPV4;
        else if (res->ai_family == AF_INET6)
            server->ip_ver = IPV6;
        memcpy(&server->sas, res->ai_addr, res->ai_addrlen);
        ok = true;
        Log("passed on an valid IP address: '%s', running with '%s'", host, res->ai_family == AF_INET ? "IPV4" : "IPV6");
    }

defer:
    if (res)
        freeaddrinfo(res);
    return ok;
}
