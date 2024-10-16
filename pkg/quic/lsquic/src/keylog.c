#include "keylog.h"
#include "logger.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_util.h"
#include <errno.h>
#include <linux/limits.h>
#include <string.h>

/* keylogging */

void setup_keylog_dir(const char* dir)
{
    keylog_dir = dir;
}

FILE* keylog_open_file(const SSL* ssl_ctx)
{
    const lsquic_conn_t* conn;
    const lsquic_cid_t* cid;
    FILE* file;
    int sz;
    char id_str[MAX_CID_LEN * 2 + 1];
    char path[PATH_MAX];

    conn = lsquic_ssl_to_conn(ssl_ctx);
    cid = lsquic_conn_id(conn);
    lsquic_hexstr(cid->idbuf, cid->len, id_str, sizeof(id_str));
    sz = snprintf(path, sizeof(path), "%s/%s.keys", keylog_dir, id_str);
    if ((size_t)sz >= sizeof(path)) {
        Log("%s: file too long", __func__);
        return NULL;
    }
    file = fopen(path, "ab");
    if (!file)
        Log("could not open %s for appending: %s", path, strerror(errno));
    return file;
}

void keylog_log_line(const SSL* ssl, const char* line)
{
    FILE* file = (FILE*)keylog_open_file(ssl);
    if (file) {
        fputs(line, file);
        fputs("\n", file);
        fclose(file);
    }
}
