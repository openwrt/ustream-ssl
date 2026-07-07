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
#include <stdlib.h>
#include <string.h>
#include <libubox/ustream.h>

#include "ustream-ssl.h"
#include "ustream-internal.h"

static void ustream_ssl_error_cb(struct uloop_timeout *t)
{
	struct ustream_ssl *us = container_of(t, struct ustream_ssl, error_timer);
	static char buffer[128];
	int error = us->error;

	if (us->notify_error)
		us->notify_error(us, error, __ustream_ssl_strerror(us->error, buffer, sizeof(buffer)));
}

static void ustream_ssl_check_conn(struct ustream_ssl *us)
{
	struct ustream *s = &us->stream;
	struct ustream_free_guard guard;
	bool connected;

	if (us->connected || us->error || us->stream.eof)
		return;

	/* the handshake may invoke notify_verify_error */
	ustream_free_guard_set(s, &guard);
	connected = __ustream_ssl_connect(us) == U_SSL_OK;
	if (ustream_free_guard_check(s, &guard))
		return;

	if (!connected)
		return;

	/* __ustream_ssl_connect() will also return U_SSL_OK when certificate
	 * verification failed!
	 *
	 * Applications may register a custom .notify_verify_error callback in the
	 * struct ustream_ssl which is called upon verification failures, but there
	 * is no straight forward way for the callback to terminate the connection
	 * initiation right away, e.g. through a true or false return value.
	 *
	 * Instead, existing implementations appear to set .eof field of the underlying
	 * ustream in the hope that this inhibits further operations on the stream.
	 *
	 * Declare this informal behaviour "official" and check for the state of the
	 * .eof member after __ustream_ssl_connect() returned, and do not write the
	 * pending data if it is set to true.
	 */

	if (us->stream.eof)
		return;

	us->connected = true;
	if (us->notify_connected) {
		ustream_free_guard_set(s, &guard);
		us->notify_connected(us);
		if (ustream_free_guard_check(s, &guard))
			return;
	}

	ustream_write_pending(s);
}

static bool __ustream_ssl_poll(struct ustream_ssl *us)
{
	struct ustream *s = &us->stream;
	struct ustream_free_guard guard;
	char *buf;
	int len, ret;
	bool more = false;

	ustream_free_guard_set(s, &guard);
	ustream_ssl_check_conn(us);
	if (ustream_free_guard_check(s, &guard))
		return false;

	if (!us->connected || us->error)
		return false;

	do {
		buf = ustream_reserve(s, 1, &len);
		if (!len)
			break;

		ret = __ustream_ssl_read(us, buf, len);
		if (ret == U_SSL_PENDING) {
			if (us->conn) {
				ustream_free_guard_set(s, &guard);
				ustream_poll(us->conn);
				if (ustream_free_guard_check(s, &guard))
					return more;
			}
			ret = __ustream_ssl_read(us, buf, len);
		}

		switch (ret) {
		case U_SSL_PENDING:
			return more;
		case U_SSL_ERROR:
			return false;
		case 0:
			s->eof = true;
			ustream_state_change(s);
			return false;
		default:
			ustream_free_guard_set(s, &guard);
			ustream_fill_read(s, ret);
			if (ustream_free_guard_check(s, &guard))
				return more;

			more = true;
			continue;
		}
	} while (1);

	return more;
}

static void ustream_ssl_notify_read(struct ustream *s, int bytes)
{
	struct ustream_ssl *us = container_of(s->next, struct ustream_ssl, stream);

	__ustream_ssl_poll(us);
}

static void ustream_ssl_notify_write(struct ustream *s, int bytes)
{
	struct ustream_ssl *us = container_of(s->next, struct ustream_ssl, stream);
	struct ustream_free_guard guard;

	ustream_free_guard_set(&us->stream, &guard);
	ustream_ssl_check_conn(us);
	if (ustream_free_guard_check(&us->stream, &guard))
		return;

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

	if (us->conn && us->conn->w.data_bytes)
		return 0;

	/* Data that the SSL library did not accept is buffered by the ustream
	 * core and retried from the buffers, i.e. with a different address and
	 * typically a different length. SSL write retry semantics require the
	 * retry to cover exactly the data of the failed call: with a shorter
	 * retry OpenSSL fails ("bad write retry"), while mbedTLS reports the
	 * retried length as written even though only the previously packaged
	 * record is sent, corrupting the stream. Cap the retry length to the
	 * length of the failed call to keep both libraries consistent.
	 */
	if (us->pending_write > 0 && len > us->pending_write)
		len = us->pending_write;

	ret = __ustream_ssl_write(us, buf, len);
	if (ret < 0) {
		us->pending_write = 0;
		return ret;
	}

	us->pending_write = len - ret;

	return ret;
}

static void ustream_ssl_set_read_blocked(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);
	unsigned int ev = ULOOP_WRITE | ULOOP_EDGE_TRIGGER;

	if (us->conn) {
		ustream_set_read_blocked(us->conn, !!s->read_blocked);
		return;
	}

	if (!s->read_blocked)
		ev |= ULOOP_READ;

	uloop_fd_add(&us->fd, ev);
}

static void ustream_ssl_free(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);

	if (us->conn) {
		us->conn->next = NULL;
		us->conn->notify_read = NULL;
		us->conn->notify_write = NULL;
		us->conn->notify_state = NULL;
	} else {
		uloop_fd_delete(&us->fd);
	}

	uloop_timeout_cancel(&us->error_timer);
	__ustream_ssl_session_free(us);
	free(us->peer_cn);

	us->ctx = NULL;
	us->ssl = NULL;
	us->conn = NULL;
	us->peer_cn = NULL;
	us->connected = false;
	us->error = false;
	us->pending_write = 0;
	us->valid_cert = false;
	us->valid_cn = false;
}

static bool ustream_ssl_poll(struct ustream *s)
{
	struct ustream_ssl *us = container_of(s, struct ustream_ssl, stream);
	struct ustream_free_guard guard;
	bool fd_poll = false;

	if (us->conn) {
		ustream_free_guard_set(s, &guard);
		fd_poll = ustream_poll(us->conn);
		if (ustream_free_guard_check(s, &guard))
			return fd_poll;
	}

	return __ustream_ssl_poll(us) || fd_poll;
}

static void ustream_ssl_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct ustream_ssl *us = container_of(fd, struct ustream_ssl, fd);

	__ustream_ssl_poll(us);

	if (!(events & ULOOP_WRITE))
		return;

	if (us->connected && !us->error && us->stream.w.data_bytes)
		ustream_write_pending(&us->stream);
}

static void ustream_ssl_stream_init(struct ustream_ssl *us)
{
	struct ustream *conn = us->conn;
	struct ustream *s = &us->stream;

	if (conn) {
		conn->notify_read = ustream_ssl_notify_read;
		conn->notify_write = ustream_ssl_notify_write;
		conn->notify_state = ustream_ssl_notify_state;
	} else {
		us->fd.cb = ustream_ssl_fd_cb;
		uloop_fd_add(&us->fd, ULOOP_READ | ULOOP_WRITE | ULOOP_EDGE_TRIGGER);
	}

	s->set_read_blocked = ustream_ssl_set_read_blocked;
	s->free = ustream_ssl_free;
	s->write = ustream_ssl_write;
	s->poll = ustream_ssl_poll;
	ustream_init_defaults(s);
}

static int _ustream_ssl_init_common(struct ustream_ssl *us)
{
	us->error_timer.cb = ustream_ssl_error_cb;

	us->ssl = __ustream_ssl_session_new(us->ctx);
	if (!us->ssl)
		return -ENOMEM;

	ustream_set_io(us);
	ustream_ssl_stream_init(us);

	if (us->server_name)
		__ustream_ssl_set_server_name(us);

	if (us->peer_cn && __ustream_ssl_update_peer_cn(us))
		return -ENOMEM;

	ustream_ssl_check_conn(us);

	return 0;
}

static int _ustream_ssl_init_fd(struct ustream_ssl *us, int fd, struct ustream_ssl_ctx *ctx, bool server)
{
	us->server = server;
	us->ctx = ctx;
	us->fd.fd = fd;

	/* Writes can block on the socket, so blocked data is buffered and
	 * retried one buffer chunk at a time. The first retried chunk must
	 * cover the record pending inside the SSL library, so it has to hold
	 * at least the maximum TLS plaintext fragment size.
	 */
	if (!us->stream.w.buffer_len)
		us->stream.w.buffer_len = 16384;

	return _ustream_ssl_init_common(us);
}

static int _ustream_ssl_init(struct ustream_ssl *us, struct ustream *conn, struct ustream_ssl_ctx *ctx, bool server)
{
	us->server = server;
	us->ctx = ctx;

	us->conn = conn;
	conn->r.max_buffers = 4;
	conn->next = &us->stream;

	return _ustream_ssl_init_common(us);
}

static int _ustream_ssl_set_peer_cn(struct ustream_ssl *us, const char *name)
{
	char *peer_cn = strdup(name);

	if (!peer_cn)
		return -ENOMEM;

	free(us->peer_cn);
	us->peer_cn = peer_cn;

	if (us->ssl)
		return __ustream_ssl_update_peer_cn(us);

	return 0;
}

const struct ustream_ssl_ops ustream_ssl_ops = {
	.context_new = __ustream_ssl_context_new,
	.context_set_crt_file = __ustream_ssl_set_crt_file,
	.context_set_key_file = __ustream_ssl_set_key_file,
	.context_add_ca_crt_file = __ustream_ssl_add_ca_crt_file,
	.context_set_ciphers = __ustream_ssl_set_ciphers,
	.context_set_require_validation = __ustream_ssl_set_require_validation,
	.context_set_debug = __ustream_ssl_set_debug,
	.context_free = __ustream_ssl_context_free,
	.init = _ustream_ssl_init,
	.init_fd = _ustream_ssl_init_fd,
	.set_peer_cn = _ustream_ssl_set_peer_cn,
};
