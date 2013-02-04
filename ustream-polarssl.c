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

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "ustream-ssl.h"
#include "ustream-internal.h"

static int urandom_fd = -1;

static int s_ustream_read(void *ctx, unsigned char *buf, size_t len)
{
	struct ustream *s = ctx;
	char *sbuf;
	int slen;

	if (s->eof)
		return 0;

	sbuf = ustream_get_read_buf(s, &slen);
	if (slen > len)
		slen = len;

	if (!slen)
		return POLARSSL_ERR_NET_WANT_READ;

	memcpy(buf, sbuf, slen);
	ustream_consume(s, slen);

	return slen;
}

static int s_ustream_write(void *ctx, const unsigned char *buf, size_t len)
{
	struct ustream *s = ctx;

	len = ustream_write(s, (const char *) buf, len, false);
	if (len < 0 || s->write_error)
		return POLARSSL_ERR_NET_SEND_FAILED;

	return len;
}

__hidden void ustream_set_io(void *ctx, void *ssl, struct ustream *conn)
{
	ssl_set_bio(ssl, s_ustream_read, conn, s_ustream_write, conn);
}

static bool urandom_init(void)
{
	if (urandom_fd > -1)
		return true;

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0)
		return false;

	return true;
}

static int _urandom(void *ctx, unsigned char *out, size_t len)
{
	read(urandom_fd, out, len);
	return 0;
}

__hidden void * __ustream_ssl_context_new(bool server)
{
	struct ustream_polarssl_ctx *uctx;

	if (!urandom_init())
		return NULL;

	uctx = calloc(1, sizeof(*uctx));
	if (!uctx)
		return NULL;

	uctx->server = server;
	rsa_init(&uctx->key, RSA_PKCS_V15, 0);

	return uctx;
}

__hidden int __ustream_ssl_set_crt_file(void *ctx, const char *file)
{
	struct ustream_polarssl_ctx *uctx = ctx;

	if (x509parse_crtfile(&uctx->cert, file))
		return -1;

	return 0;
}

__hidden int __ustream_ssl_set_key_file(void *ctx, const char *file)
{
	struct ustream_polarssl_ctx *uctx = ctx;

	if (x509parse_keyfile(&uctx->key, file, NULL))
		return -1;

	return 0;
}

__hidden void __ustream_ssl_context_free(void *ctx)
{
	struct ustream_polarssl_ctx *uctx = ctx;

	rsa_free(&uctx->key);
	x509_free(&uctx->cert);
	free(ctx);
}

static void ustream_ssl_error(struct ustream_ssl *us, int ret)
{
	us->error = ret;
	uloop_timeout_set(&us->error_timer, 0);
}

static bool ssl_do_wait(int ret)
{
	switch(ret) {
	case POLARSSL_ERR_NET_WANT_READ:
	case POLARSSL_ERR_NET_WANT_WRITE:
		return true;
	default:
		return false;
	}
}

__hidden enum ssl_conn_status __ustream_ssl_connect(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	int r;

	r = ssl_handshake(ssl);
	if (r == 0)
		return U_SSL_OK;

	if (ssl_do_wait(r))
		return U_SSL_PENDING;

	ustream_ssl_error(us, r);
	return U_SSL_ERROR;
}

__hidden int __ustream_ssl_write(struct ustream_ssl *us, const char *buf, int len)
{
	void *ssl = us->ssl;
	int ret = ssl_write(ssl, (const unsigned char *) buf, len);

	if (ret < 0) {
		if (ssl_do_wait(ret))
			return 0;

		ustream_ssl_error(us, ret);
		return -1;
	}

	return ret;
}

__hidden int __ustream_ssl_read(struct ustream_ssl *us, char *buf, int len)
{
	int ret = ssl_read(us->ssl, (unsigned char *) buf, len);

	if (ret < 0) {
		if (ssl_do_wait(ret))
			return U_SSL_PENDING;

		ustream_ssl_error(us, ret);
		return U_SSL_ERROR;
	}

	return ret;
}

__hidden void *__ustream_ssl_session_new(void *ctx)
{
	struct ustream_polarssl_ctx *uctx = ctx;
	ssl_context *ssl;
	int ep, auth;

	ssl = calloc(1, sizeof(ssl_context));
	if (!ssl)
		return NULL;

	if (ssl_init(ssl)) {
		free(ssl);
		return NULL;
	}

	if (uctx->server) {
		ep = SSL_IS_SERVER;
		auth = SSL_VERIFY_NONE;
	} else {
		ep = SSL_IS_CLIENT;
		auth = SSL_VERIFY_OPTIONAL;
	}

	ssl_set_endpoint(ssl, ep);
	ssl_set_authmode(ssl, auth);
	ssl_set_rng(ssl, _urandom, NULL);

	if (uctx->server) {
		if (uctx->cert.next)
			ssl_set_ca_chain(ssl, uctx->cert.next, NULL, NULL);
		ssl_set_own_cert(ssl, &uctx->cert, &uctx->key);
	}

	ssl_session_reset(ssl);

	return ssl;
}

__hidden void __ustream_ssl_session_free(void *ssl)
{
	ssl_free(ssl);
	free(ssl);
}
