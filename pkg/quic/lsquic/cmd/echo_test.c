#include "logger.h"
#include "server.h"
#include <stdlib.h>

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

    ok = new_server(&server, "./keylog");
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
