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

#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <libubox/ustream.h>
#include "ustream-io.h"
#include "ustream-ssl.h"

static void ssl_init(void)
{
	static bool _init = false;

	if (_init)
		return;

	SSL_load_error_strings();
	SSL_library_init();

	_init = true;
}

static void ustream_ssl_error_cb(struct uloop_timeout *t)
{
	struct ustream_ssl *us = container_of(t, struct ustream_ssl, error_timer);
	static char buffer[128];
	int error = us->error;

	if (us->notify_error)
		us->notify_error(us, error, ERR_error_string(us->error, buffer));
}

static void ustream_ssl_error(struct ustream_ssl *us, int error)
{
	us->error = error;
	uloop_timeout_set(&us->error_timer, 0);
}

static void ustream_ssl_check_conn(struct ustream_ssl *us)
{
	int ret;

	if (us->connected || us->error)
		return;

	if (us->server)
		ret = SSL_accept(us->ssl);
	else
		ret = SSL_connect(us->ssl);

	if (ret == 1) {
		us->connected = true;
		if (us->notify_connected)
			us->notify_connected(us);
		return;
	}

	ret = SSL_get_error(us->ssl, ret);
	if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE)
		return;

	ustream_ssl_error(us, ret);
}

static bool __ustream_ssl_poll(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s->next, struct ustream_ssl, stream);
	char *buf;
	int len, ret;
	bool more = false;

	ustream_ssl_check_conn(us);
	if (!us->connected || us->error)
		return false;

	do {
		buf = ustream_reserve(&us->stream, 1, &len);
		if (!len)
			break;

		ret = SSL_read(us->ssl, buf, len);
		if (ret < 0) {
			ret = SSL_get_error(us->ssl, ret);

			if (ret == SSL_ERROR_WANT_READ)
				break;

			ustream_ssl_error(us, ret);
			break;
		}
		if (ret == 0) {
			us->stream.eof = true;
			ustream_state_change(&us->stream);
			break;
		}

		ustream_fill_read(&us->stream, ret);
		more = true;
	} while (1);

	return more;
}

static void ustream_ssl_notify_read(struct ustream *s, int bytes)
{
	__ustream_ssl_poll(s);
}

static void ustream_ssl_notify_write(struct ustream *s, int bytes)
{
	struct ustream_ssl *us = container_of(s->next, struct ustream_ssl, stream);

	ustream_ssl_check_conn(us);
	ustream_write_pending(s->next);
}

static void ustream_ssl_notify_state(struct ustream *s)
{
	s->next->write_error = true;
	ustream_state_change(s->next);
}

static int ustream_ssl_write(struct ustream *s, const char *buf, int len, bool more)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);
	int ret;

	if (!us->connected || us->error)
		return 0;

	if (us->conn->w.data_bytes)
		return 0;

	ret = SSL_write(us->ssl, buf, len);
	if (ret < 0) {
		int err = SSL_get_error(us->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE)
			return 0;
	}

	return ret;
}

static void ustream_ssl_set_read_blocked(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);

	ustream_set_read_blocked(us->conn, !!s->read_blocked);
}

static void ustream_ssl_free(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);

	if (us->conn) {
		us->conn->next = NULL;
		us->conn->notify_read = NULL;
		us->conn->notify_write = NULL;
		us->conn->notify_state = NULL;
	}

	uloop_timeout_cancel(&us->error_timer);
	SSL_shutdown(us->ssl);
	SSL_free(us->ssl);
	us->ctx = NULL;
	us->ssl = NULL;
	us->conn = NULL;
	us->connected = false;
	us->error = false;
}

static bool ustream_ssl_poll(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);
	bool fd_poll;

	fd_poll = ustream_poll(us->conn);
	return __ustream_ssl_poll(s) || fd_poll;
}

static void ustream_ssl_stream_init(struct ustream_ssl *us)
{
	struct ustream *conn = us->conn;
	struct ustream *s = &us->stream;

	conn->notify_read = ustream_ssl_notify_read;
	conn->notify_write = ustream_ssl_notify_write;
	conn->notify_state = ustream_ssl_notify_state;

	s->free = ustream_ssl_free;
	s->write = ustream_ssl_write;
	s->poll = ustream_ssl_poll;
	s->set_read_blocked = ustream_ssl_set_read_blocked;
	ustream_init_defaults(s);
}

static void *_ustream_ssl_context_new(bool server)
{
	SSL_CTX *c;
	const void *m;

	ssl_init();

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

	return c;
}

static int _ustream_ssl_context_set_crt_file(void *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
	if (ret < 1)
		ret = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_ASN1);

	if (ret < 1)
		return -1;

	return 0;
}

static int _ustream_ssl_context_set_key_file(void *ctx, const char *file)
{
	int ret;

	ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
	if (ret < 1)
		ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_ASN1);

	if (ret < 1)
		return -1;

	return 0;
}

static void _ustream_ssl_context_free(void *ctx)
{
	SSL_CTX_free(ctx);
}

static int _ustream_ssl_init(struct ustream_ssl *us, struct ustream *conn, void *ctx, bool server)
{
	us->error_timer.cb = ustream_ssl_error_cb;
	us->server = server;
	us->conn = conn;
	us->ctx = ctx;

	us->ssl = SSL_new(us->ctx);
	if (!us->ssl)
		return -ENOMEM;

	conn->next = &us->stream;
	ustream_set_io(ctx, us->ssl, conn);
	ustream_ssl_stream_init(us);

	return 0;
}

const struct ustream_ssl_ops ustream_ssl_ops = {
	.context_new = _ustream_ssl_context_new,
	.context_set_crt_file = _ustream_ssl_context_set_crt_file,
	.context_set_key_file = _ustream_ssl_context_set_key_file,
	.context_free = _ustream_ssl_context_free,
	.init = _ustream_ssl_init,
};
