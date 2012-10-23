#ifndef __USTREAM_BIO_H
#define __USTREAM_BIO_H

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ustream-ssl.h"

void ustream_set_io(SSL_CTX *ctx, SSL *ssl, struct ustream *s);

#endif
