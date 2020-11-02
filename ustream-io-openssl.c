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
#include "openssl_bio_compat.h"
#include "ustream-internal.h"

static int
s_ustream_new(BIO *b)
{
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	BIO_clear_flags(b, ~0);
	return 1;
}

static int
s_ustream_free(BIO *b)
{
	if (!b)
		return 0;

	BIO_set_data(b, NULL);
	BIO_set_init(b, 0);
	BIO_clear_flags(b, ~0);
	BIO_meth_free(b->method);
	return 1;
}

static int
s_ustream_read(BIO *b, char *buf, int len)
{
	struct ustream *s;
	char *sbuf;
	int slen;

	if (!buf || len <= 0)
		return 0;

	s = (struct ustream *)BIO_get_data(b);
	if (!s)
		return 0;

	sbuf = ustream_get_read_buf(s, &slen);

	BIO_clear_retry_flags(b);
	if (!slen) {
		BIO_set_retry_read(b);
		return -1;
	}

	if (slen > len)
		slen = len;

	memcpy(buf, sbuf, slen);
	ustream_consume(s, slen);

	return slen;
}

static int
s_ustream_write(BIO *b, const char *buf, int len)
{
	struct ustream *s;

	if (!buf || len <= 0)
		return 0;

	s = (struct ustream *)BIO_get_data(b);
	if (!s)
		return 0;

	if (s->write_error)
		return len;

	return ustream_write(s, buf, len, false);
}

static int
s_ustream_gets(BIO *b, char *buf, int len)
{
	return -1;
}

static int
s_ustream_puts(BIO *b, const char *str)
{
	return s_ustream_write(b, str, strlen(str));
}

static long s_ustream_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	default:
		return 0;
	};
}

static BIO *ustream_bio_new(struct ustream *s)
{
	BIO *bio;

	BIO_METHOD *methods_ustream;

	methods_ustream = BIO_meth_new(100 | BIO_TYPE_SOURCE_SINK, "ustream");
	BIO_meth_set_write(methods_ustream, s_ustream_write);
	BIO_meth_set_read(methods_ustream, s_ustream_read);
	BIO_meth_set_puts(methods_ustream, s_ustream_puts);
	BIO_meth_set_gets(methods_ustream, s_ustream_gets);
	BIO_meth_set_ctrl(methods_ustream, s_ustream_ctrl);
	BIO_meth_set_create(methods_ustream, s_ustream_new);
	BIO_meth_set_destroy(methods_ustream, s_ustream_free);
	bio = BIO_new(methods_ustream);
	BIO_set_data(bio, s);

	return bio;
}

__hidden void ustream_set_io(struct ustream_ssl_ctx *ctx, void *ssl, struct ustream *conn)
{
	BIO *bio = ustream_bio_new(conn);
	SSL_set_bio(ssl, bio, bio);
}
