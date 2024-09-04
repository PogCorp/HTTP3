#include "openssl/base.h"
#include <stdio.h>

/* server keylogging */
FILE* keylog_open_file(const SSL* ssl);
void keylog_log_line(const SSL* ssl, const char* line);
void setup_keylog_dir(const char* dir);
