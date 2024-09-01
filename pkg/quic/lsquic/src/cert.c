#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string.h>

#include "cert.h"
#include "logger.h"

char *format_sni(const char *hostname, const char *certfile,
                 const char *keyfile);

// TODO: add the alpn setter in the server.c

// TODO: arg must be set to the server alpn context
int select_alpn_callback(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
  const char *alpn = arg;
  int response;

  response = SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                                   (unsigned char *)alpn, strlen(alpn));
  if (response == OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_OK;
  else {
    Log("no supported protocol could be selected for %s", (char *)in);
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

struct ssl_ctx_st *lookup_cert_callback(void *cert_ctx,
                                        const struct sockaddr *_,
                                        const char *sni) {
  struct lsquic_hash_elem *elem;
  struct certificateElem *cert;

  if (!cert_ctx)
    return NULL;

  if (sni)
    elem = lsquic_hash_find(cert_ctx, sni, strlen(sni));
  else {
    Log("SNI not set, defaulting to first certificate in table");
    elem = lsquic_hash_first(cert_ctx);
  }

  if (elem) {
    cert = lsquic_hashelem_getdata(elem);
    if (cert)
      return cert->ssl_ctx;
  }

  return NULL;
}

bool load_certificate(struct lsquic_hash *certs, const char *hostname,
                      const char *certfile, const char *keyfile, char *alpn,
                      bool early_data) {
  bool ok = false;
  struct certificateElem *cert = NULL;
  EVP_PKEY *pkey = NULL;
  FILE *f = NULL;
  char *sni = format_sni(hostname, certfile, keyfile);

  cert = calloc(1, sizeof(*cert));
  cert->sni = sni;
  cert->ssl_ctx = SSL_CTX_new(TLS_method());
  if (!cert->ssl_ctx) {
    Log("at %s, SSL_CTX_new failed", __func__);
    goto defer;
  }
  SSL_CTX_set_min_proto_version(cert->ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(cert->ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_default_verify_paths(cert->ssl_ctx);
  SSL_CTX_set_alpn_select_cb(cert->ssl_ctx, select_alpn_callback, alpn);
  if (early_data) {
    SSL_CTX_set_early_data_enabled(cert->ssl_ctx, 1);
  }
  if (SSL_CTX_use_certificate_chain_file(cert->ssl_ctx, certfile) != 1) {
    Log("at %s, SSL_CTX_use_certificate_chain_file failed: %s", __func__,
        certfile);
    goto defer;
  }
  if (SSL_CTX_use_PrivateKey_file(cert->ssl_ctx, keyfile, SSL_FILETYPE_PEM) !=
      1) {
    Log("at %s, SSL_CTX_use_PrivateKey_file failed", __func__);
    goto defer;
  }

  const int prev = SSL_CTX_set_session_cache_mode(cert->ssl_ctx, 1);
  Log("set SSL session cache mode to 1, previous value was %d", prev);

  if (lsquic_hash_insert(certs, cert->sni, strlen(cert->sni), cert,
                         &cert->hash_el))
    ok = true;
  else
    Log("certificate with sni %s was not inserted in certificate table",
        cert->sni);

  return ok;

defer:
  if (!ok) {
    if (cert) {
      free(cert->sni);
      free(cert);
    }
  }
  return ok;
}

void clean_certificates(struct lsquic_hash *certs) {
  struct lsquic_hash_elem *elem;
  struct certificateElem *cert;

  for (elem = lsquic_hash_first(certs); elem; elem = lsquic_hash_next(certs)) {
    cert = lsquic_hashelem_getdata(elem);
    SSL_CTX_free(cert->ssl_ctx);
    free(cert->sni);
    free(cert);
  }
  lsquic_hash_destroy(certs);
}

// TODO: write tests
char *format_sni(const char *hostname, const char *certfile,
                 const char *keyfile) {
  const unsigned long hostname_len = strlen(hostname);
  const unsigned long certfile_len = strlen(certfile);
  const unsigned long keyfile_len = strlen(keyfile);
  const unsigned long sni_len = hostname_len + certfile_len + keyfile_len + 3;

  char *sni = malloc(sni_len * sizeof(char));
  memcpy(sni, hostname, hostname_len);
  *(sni + hostname_len) = '\0';
  memcpy(sni + hostname_len + 1, certfile, certfile_len);
  *(sni + hostname_len + certfile_len + 1) = '\0';
  memcpy(sni + hostname_len + certfile_len + 2, keyfile, keyfile_len);
  *(sni + hostname_len + certfile_len + 1) = '\0';

  return sni;
}
