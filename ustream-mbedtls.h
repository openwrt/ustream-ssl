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

#ifndef __USTREAM_POLARSSL_H
#define __USTREAM_POLARSSL_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/entropy.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

struct ustream_ssl_ctx {
	mbedtls_ssl_config conf;
	mbedtls_pk_context key;
	mbedtls_x509_crt ca_cert;
	mbedtls_x509_crt cert;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif
	ustream_ssl_debug_cb debug_cb;
	void *debug_cb_priv;
	bool server;
	int *ciphersuites;

	void *session_data;
	size_t session_data_len;
};

static inline char *__ustream_ssl_strerror(int error, char *buffer, int len)
{
	mbedtls_strerror(error, buffer, len);
	return buffer;
}

static inline void __ustream_ssl_set_server_name(struct ustream_ssl *us)
{
	mbedtls_ssl_set_hostname(us->ssl, us->server_name);
}

static inline void __ustream_ssl_update_peer_cn(struct ustream_ssl *us)
{
	mbedtls_ssl_set_hostname(us->ssl, us->peer_cn);
}

void *__ustream_ssl_session_new(struct ustream_ssl_ctx *ctx);

#endif
