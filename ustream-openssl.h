/*
 * ustream-ssl - library for SSL over ustream
 *
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __USTREAM_OPENSSL_H
#define __USTREAM_OPENSSL_H

#if defined(HAVE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include <stdbool.h>

struct ustream_ssl_ctx {
	SSL_CTX *ssl;
	BIO *debug_bio;
	ustream_ssl_debug_cb debug_cb;
	void *debug_cb_priv;
};

struct bio_ctx {
	BIO_METHOD *meth;
	struct ustream *stream;
};

static inline void *__ustream_ssl_session_new(struct ustream_ssl_ctx *ctx)
{
	return SSL_new(ctx->ssl);
}

static inline char *__ustream_ssl_strerror(int error, char *buffer, int len)
{
	return ERR_error_string(error, buffer);
}

static inline void __ustream_ssl_update_peer_cn(struct ustream_ssl *us)
{
}

static inline void __ustream_ssl_set_server_name(struct ustream_ssl *us)
{
	SSL_set_tlsext_host_name(us->ssl, us->server_name);
}

#endif
