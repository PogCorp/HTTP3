#include <lsquic.h>
#include <sys/queue.h> // HACK: this is necessary for imports to access internal types of lsquic
#pragma once

typedef struct engine {
    struct lsquic_engine_settings settings;
    lsquic_engine_t* quic;
} LsquicEngine;
