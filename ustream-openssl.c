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

#include "ustream-ssl.h"
#include "ustream-internal.h"

__hidden struct ustream_ssl_ctx *
__ustream_ssl_context_new(bool server)
{
	static bool _init = false;
	const void *m;
	SSL_CTX *c;

	if (!_init) {
		SSL_load_error_strings();
		SSL_library_init();
		_init = true;
	}

#ifdef CYASSL_OPENSSL_H_
	if (server)
		m = SSLv23_server_method();
	else
		m = SSLv23_client_method();
#else
	if (server)
		m = TLSv1_server_method();
	else
		m = TLSv1_client_method();
#endif

	c = SSL_CTX_new((void *) m);
	if (!c)
		return NULL;

	if (server)
		SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);

	return (void *) c;
}

__hidden int __ustream_ssl_set_crt_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_use_certificate_file((void *) ctx, file, SSL_FILETYPE_PEM);
	if (ret < 1)
		ret = SSL_CTX_use_certificate_file((void *) ctx, file, SSL_FILETYPE_ASN1);

	if (ret < 1)
		return -1;

	return 0;
}

__hidden int __ustream_ssl_set_key_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_use_PrivateKey_file((void *) ctx, file, SSL_FILETYPE_PEM);
	if (ret < 1)
		ret = SSL_CTX_use_PrivateKey_file((void *) ctx, file, SSL_FILETYPE_ASN1);

	if (ret < 1)
		return -1;

	return 0;
}

__hidden void __ustream_ssl_context_free(struct ustream_ssl_ctx *ctx)
{
	SSL_CTX_free((void *) ctx);
}

static void ustream_ssl_error(struct ustream_ssl *us, int ret)
{
	us->error = ret;
	uloop_timeout_set(&us->error_timer, 0);
}

__hidden enum ssl_conn_status __ustream_ssl_connect(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	int r;

	if (us->server)
		r = SSL_accept(ssl);
	else
		r = SSL_connect(ssl);

	if (r == 1)
		return U_SSL_OK;

	r = SSL_get_error(ssl, r);
	if (r == SSL_ERROR_WANT_READ || r == SSL_ERROR_WANT_WRITE)
		return U_SSL_PENDING;

	ustream_ssl_error(us, r);
	return U_SSL_ERROR;
}

__hidden int __ustream_ssl_write(struct ustream_ssl *us, const char *buf, int len)
{
	void *ssl = us->ssl;
	int ret = SSL_write(ssl, buf, len);

	if (ret < 0) {
		int err = SSL_get_error(ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE)
			return 0;

		ustream_ssl_error(us, err);
		return -1;
	}

	return ret;
}

__hidden int __ustream_ssl_read(struct ustream_ssl *us, char *buf, int len)
{
	int ret = SSL_read(us->ssl, buf, len);

	if (ret < 0) {
		ret = SSL_get_error(us->ssl, ret);
		if (ret == SSL_ERROR_WANT_READ)
			return U_SSL_PENDING;

		ustream_ssl_error(us, ret);
		return U_SSL_ERROR;
	}

	return ret;
}

