#include "logger.c"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

typedef union socketAddress {
    struct sockaddr sa;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
} SocketAddress;

static void get_address_info(const char* host_name, int port_num, SocketAddress* address)
{
    if (inet_pton(AF_INET, host_name, &address->addr4.sin_addr)) {
        address->addr4.sin_family = AF_INET;
        address->addr4.sin_port = port_num;
    } else if (memset(&address->addr6, 0, sizeof(address->addr6)),
        inet_pton(AF_INET6, host_name, &address->addr6.sin6_addr)) {
        address->addr6.sin6_family = AF_INET6;
        address->addr6.sin6_port = port_num;
    } else {
        log("passed on an valid IP address: '%s'", host_name);
        exit(EXIT_FAILURE);
    }
}
