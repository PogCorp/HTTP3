#include "logger.h"
#include "server.h"
#include <stdlib.h>

#define INIT_PROTO_LEN(alpn, alpn_size)                                \
    do {                                                               \
        for (int i = 0; i < sizeof((alpn)) / sizeof((alpn[0])); i++) { \
            alpn_size[i] = strlen(alpn[i]);                            \
        }                                                              \
    } while (0)

int main(int _, char* argv[])
{
    Server server;
    bool ok;
    char* alpn[] = {
        "echo",
    };
    size_t alpn_size[sizeof(alpn) / sizeof(alpn[0])];
    INIT_PROTO_LEN(alpn, alpn_size);

    char* certfile = getenv("CERTFILE");
    char* keyfile = getenv("KEYFILE");
    set_logger_fd(stdout);
    if (!certfile || !keyfile) {
        Log("failed to load cerfile or keyfile\n(cerfile,keyfile)=(%s,%s)\n", certfile, keyfile);
        return EXIT_FAILURE;
    }

    ok = new_server(&server, "./keylog", alpn, alpn_size, sizeof(alpn_size) / sizeof(alpn_size[0]));
    if (!ok) {
        Log("failure while creating new_server");
        return EXIT_FAILURE;
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
