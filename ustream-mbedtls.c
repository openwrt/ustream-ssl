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
#include <string.h>

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
		return MBEDTLS_ERR_SSL_WANT_READ;

	memcpy(buf, sbuf, slen);
	ustream_consume(s, slen);

	return slen;
}

static int s_ustream_write(void *ctx, const unsigned char *buf, size_t len)
{
	struct ustream *s = ctx;
	int ret;

	ret = ustream_write(s, (const char *) buf, len, false);
	if (ret < 0 || s->write_error)
		return MBEDTLS_ERR_NET_SEND_FAILED;

	return ret;
}

__hidden void ustream_set_io(struct ustream_ssl_ctx *ctx, void *ssl, struct ustream *conn)
{
	mbedtls_ssl_set_bio(ssl, conn, s_ustream_write, s_ustream_read, NULL);
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
	if (read(urandom_fd, out, len) < 0)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

	return 0;
}

#define TLS_DEFAULT_CIPHERS			\
    TLS_CIPHER(AES_256_CBC_SHA256)		\
    TLS_CIPHER(AES_256_GCM_SHA384)		\
    TLS_CIPHER(AES_256_CBC_SHA)			\
    TLS_CIPHER(CAMELLIA_256_CBC_SHA256)		\
    TLS_CIPHER(CAMELLIA_256_CBC_SHA)		\
    TLS_CIPHER(AES_128_CBC_SHA256)		\
    TLS_CIPHER(AES_128_GCM_SHA256)		\
    TLS_CIPHER(AES_128_CBC_SHA)			\
    TLS_CIPHER(CAMELLIA_128_CBC_SHA256)		\
    TLS_CIPHER(CAMELLIA_128_CBC_SHA)		\
    TLS_CIPHER(3DES_EDE_CBC_SHA)

static const int default_ciphersuites_nodhe[] =
{
#define TLS_CIPHER(v)				\
	MBEDTLS_TLS_RSA_WITH_##v,
	TLS_DEFAULT_CIPHERS
#undef TLS_CIPHER
	0
};

static const int default_ciphersuites[] =
{
#define TLS_CIPHER(v)				\
	MBEDTLS_TLS_DHE_RSA_WITH_##v,		\
	MBEDTLS_TLS_RSA_WITH_##v,
	TLS_DEFAULT_CIPHERS
#undef TLS_CIPHER
	0
};


__hidden struct ustream_ssl_ctx *
__ustream_ssl_context_new(bool server)
{
	struct ustream_ssl_ctx *ctx;
	mbedtls_ssl_config *conf;
	int ep;

	if (!urandom_init())
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->server = server;
	mbedtls_pk_init(&ctx->key);
	mbedtls_x509_crt_init(&ctx->cert);
	mbedtls_x509_crt_init(&ctx->ca_cert);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&ctx->cache);
	mbedtls_ssl_cache_set_timeout(&ctx->cache, 30 * 60);
	mbedtls_ssl_cache_set_max_entries(&ctx->cache, 5);
#endif

	conf = &ctx->conf;
	mbedtls_ssl_config_init(conf);

	if (server) {
		mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites_nodhe);
		ep = MBEDTLS_SSL_IS_SERVER;
	} else {
		mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites);
		ep = MBEDTLS_SSL_IS_CLIENT;
	}

	mbedtls_ssl_config_defaults(conf, ep, MBEDTLS_SSL_TRANSPORT_STREAM,
				    MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(conf, _urandom, NULL);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_conf_session_cache(conf, &ctx->cache,
				       mbedtls_ssl_cache_get,
				       mbedtls_ssl_cache_set);
#endif
	return ctx;
}

static void ustream_ssl_update_own_cert(struct ustream_ssl_ctx *ctx)
{
	if (!ctx->cert.version)
		return;

	if (!ctx->server) {
		mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cert, NULL);
		return;
	}

	if (!ctx->key.pk_info)
		return;

	if (ctx->cert.next)
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->cert.next, NULL);
	mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->key);
}

__hidden int __ustream_ssl_add_ca_crt_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = mbedtls_x509_crt_parse_file(&ctx->ca_cert, file);
	if (ret)
		return -1;

	mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca_cert, NULL);
	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	return 0;
}

__hidden int __ustream_ssl_set_crt_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = mbedtls_x509_crt_parse_file(&ctx->cert, file);
	if (ret)
		return -1;

	ustream_ssl_update_own_cert(ctx);
	return 0;
}

__hidden int __ustream_ssl_set_key_file(struct ustream_ssl_ctx *ctx, const char *file)
{
	int ret;

	ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL);
	if (ret)
		return -1;

	ustream_ssl_update_own_cert(ctx);
	return 0;
}

__hidden void __ustream_ssl_context_free(struct ustream_ssl_ctx *ctx)
{
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&ctx->cache);
#endif
	mbedtls_pk_free(&ctx->key);
	mbedtls_x509_crt_free(&ctx->ca_cert);
	mbedtls_x509_crt_free(&ctx->cert);
	mbedtls_ssl_config_free(&ctx->conf);
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
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return true;
	default:
		return false;
	}
}

static void ustream_ssl_verify_cert(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	const char *msg = NULL;
	bool cn_mismatch;
	int r;

	r = mbedtls_ssl_get_verify_result(ssl);
	cn_mismatch = r & MBEDTLS_X509_BADCERT_CN_MISMATCH;
	r &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;

	if (r & MBEDTLS_X509_BADCERT_EXPIRED)
		msg = "certificate has expired";
	else if (r & MBEDTLS_X509_BADCERT_REVOKED)
		msg = "certificate has been revoked";
	else if (r & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
		msg = "certificate is self-signed or not signed by a trusted CA";
	else
		msg = "unknown error";

	if (r) {
		if (us->notify_verify_error)
			us->notify_verify_error(us, r, msg);
		return;
	}

	if (!cn_mismatch)
		us->valid_cn = true;
}

__hidden enum ssl_conn_status __ustream_ssl_connect(struct ustream_ssl *us)
{
	void *ssl = us->ssl;
	int r;

	r = mbedtls_ssl_handshake(ssl);
	if (r == 0) {
		ustream_ssl_verify_cert(us);
		return U_SSL_OK;
	}

	if (ssl_do_wait(r))
		return U_SSL_PENDING;

	ustream_ssl_error(us, r);
	return U_SSL_ERROR;
}

__hidden int __ustream_ssl_write(struct ustream_ssl *us, const char *buf, int len)
{
	void *ssl = us->ssl;
	int done = 0, ret = 0;

	while (done != len) {
		ret = mbedtls_ssl_write(ssl, (const unsigned char *) buf + done, len - done);

		if (ret < 0) {
			if (ssl_do_wait(ret))
				return done;

			ustream_ssl_error(us, ret);
			return -1;
		}

		done += ret;
	}

	return done;
}

__hidden int __ustream_ssl_read(struct ustream_ssl *us, char *buf, int len)
{
	int ret = mbedtls_ssl_read(us->ssl, (unsigned char *) buf, len);

	if (ret < 0) {
		if (ssl_do_wait(ret))
			return U_SSL_PENDING;

		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			return 0;

		ustream_ssl_error(us, ret);
		return U_SSL_ERROR;
	}

	return ret;
}

__hidden void *__ustream_ssl_session_new(struct ustream_ssl_ctx *ctx)
{
	mbedtls_ssl_context *ssl;

	ssl = calloc(1, sizeof(*ssl));
	if (!ssl)
		return NULL;

	mbedtls_ssl_init(ssl);

	if (mbedtls_ssl_setup(ssl, &ctx->conf)) {
		free(ssl);
		return NULL;
	}

	return ssl;
}

__hidden void __ustream_ssl_session_free(void *ssl)
{
	mbedtls_ssl_free(ssl);
	free(ssl);
}
