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

#include <string.h>
#include <ctype.h>
#include <openssl/x509v3.h>
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
		m = TLSv1_2_server_method();
	else
		m = TLSv1_2_client_method();
#endif

	c = SSL_CTX_new((void *) m);
	if (!c)
		return NULL;

	SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_quiet_shutdown(c, 1);

	return (void *) c;
}

__hidden int __ustream_ssl_add_ca_crt_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_load_verify_locations((void *) ctx, file, NULL);
	if (ret < 1)
		return -1;

	return 0;
}

__hidden int __ustream_ssl_set_crt_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_use_certificate_chain_file((void *) ctx, file);
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

void __ustream_ssl_session_free(void *ssl)
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
}

static void ustream_ssl_error(struct ustream_ssl *us, int ret)
{
	us->error = ret;
	uloop_timeout_set(&us->error_timer, 0);
}

#ifndef CYASSL_OPENSSL_H_

static bool ustream_ssl_verify_cn(struct ustream_ssl *us, X509 *cert)
{
	int ret;

	if (!us->peer_cn)
		return false;

	ret = X509_check_host(cert, us->peer_cn, 0, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL);
	return ret == 1;
}


static void ustream_ssl_verify_cert(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	X509 *cert;
	int res;

	res = SSL_get_verify_result(ssl);
	if (res != X509_V_OK) {
		if (us->notify_verify_error)
			us->notify_verify_error(us, res, X509_verify_cert_error_string(res));
		return;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert)
		return;

	us->valid_cert = true;
	us->valid_cn = ustream_ssl_verify_cn(us, cert);
	X509_free(cert);
}

#endif

__hidden enum ssl_conn_status __ustream_ssl_connect(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	int r;

	if (us->server)
		r = SSL_accept(ssl);
	else
		r = SSL_connect(ssl);

	if (r == 1) {
#ifndef CYASSL_OPENSSL_H_
		ustream_ssl_verify_cert(us);
#endif
		return U_SSL_OK;
	}

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

