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

#include <libubox/ustream.h>

#include "ustream-ssl.h"
#include "ustream-internal.h"

static int s_ustream_read(char *buf, int len, void *ctx)
{
	struct ustream *s = ctx;
	char *sbuf;
	int slen;

	if (s->eof)
		return -3;

	sbuf = ustream_get_read_buf(s, &slen);
	if (slen > len)
		slen = len;

	if (!slen)
		return -2;

	memcpy(buf, sbuf, slen);
	ustream_consume(s, slen);

	return slen;
}

static int s_ustream_write(char *buf, int len, void *ctx)
{
	struct ustream *s = ctx;

	if (s->write_error)
		return len;

	return ustream_write(s, buf, len, false);
}

static int io_recv_cb(SSL* ssl, char *buf, int sz, void *ctx)
{
	return s_ustream_read(buf, sz, ctx);
}

static int io_send_cb(SSL* ssl, char *buf, int sz, void *ctx)
{
	return s_ustream_write(buf, sz, ctx);
}

__hidden void ustream_set_io(struct ustream_ssl *us)
{
	if (!us->conn) {
		wolfSSL_set_fd(us->ssl, us->fd.fd);
		return;
	}

	wolfSSL_SSLSetIORecv(us->ssl, io_recv_cb);
	wolfSSL_SSLSetIOSend(us->ssl, io_send_cb);
	wolfSSL_SetIOReadCtx(us->ssl, us->conn);
	wolfSSL_SetIOWriteCtx(us->ssl, us->conn);
}
