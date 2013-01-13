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

#ifndef __USTREAM_SSL_H
#define __USTREAM_SSL_H

struct ustream_ssl {
	struct ustream stream;
	struct ustream *conn;
	struct uloop_timeout error_timer;

	void (*notify_connected)(struct ustream_ssl *us);
	void (*notify_error)(struct ustream_ssl *us, int error, const char *str);

	void *ctx;
	void *ssl;

	int error;
	bool connected;
	bool server;
};

struct ustream_ssl_ops {
	void *(*context_new)(bool server);
	int (*context_set_crt_file)(void *ctx, const char *file);
	int (*context_set_key_file)(void *ctx, const char *file);
	void (*context_free)(void *ctx);

	int (*init)(struct ustream_ssl *us, struct ustream *conn, void *ctx, bool server);
};

extern const struct ustream_ssl_ops ustream_ssl_ops;

#define ustream_ssl_context_new			ustream_ssl_ops.context_new
#define ustream_ssl_context_set_crt_file	ustream_ssl_ops.context_set_crt_file
#define ustream_ssl_context_set_key_file	ustream_ssl_ops.context_set_key_file
#define ustream_ssl_context_free		ustream_ssl_ops.context_free
#define ustream_ssl_init			ustream_ssl_ops.init

#endif
