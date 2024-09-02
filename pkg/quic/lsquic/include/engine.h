#include <lsquic.h>
#pragma once

typedef struct engine {
    struct lsquic_engine_settings settings;
    lsquic_engine_t* quic;
} LsquicEngine;
