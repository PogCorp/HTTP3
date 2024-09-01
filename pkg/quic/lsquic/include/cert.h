#include <openssl/base.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include "lsquic_hash.h"

struct certificateElem {
  char *sni;
  struct ssl_ctx_st *ssl_ctx;
  struct lsquic_hash_elem hash_el;
};

int select_alpn_callback(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg);

struct ssl_ctx_st *
lookup_cert_callback(void *cert_ctx, const struct sockaddr *_, const char *sni);

bool load_certificate(struct lsquic_hash *certs, const char *hostname,
                      const char *certfile, const char *keyfile, char *alpn,
                      bool early_data);

void clean_certificates(struct lsquic_hash *certs);
