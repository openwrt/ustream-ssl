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
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "ustream-ssl.h"
#include "ustream-internal.h"

static int s_ustream_read(void *ctx, unsigned char *buf, size_t len)
{
	struct ustream *s = ctx;
	char *sbuf;
	int slen;

	if (s->eof)
		return 0;

	sbuf = ustream_get_read_buf(s, &slen);
	if ((size_t) slen > len)
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

static int _random(void *ctx, unsigned char *out, size_t len)
{
	ssize_t ret;

	ret = getrandom(out, len, 0);
	if (ret < 0 || (size_t)ret != len)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

	return 0;
}

#define AES_GCM_CIPHERS(v)				\
	MBEDTLS_TLS_##v##_WITH_AES_128_GCM_SHA256,	\
	MBEDTLS_TLS_##v##_WITH_AES_256_GCM_SHA384

#define AES_CBC_CIPHERS(v)				\
	MBEDTLS_TLS_##v##_WITH_AES_128_CBC_SHA,		\
	MBEDTLS_TLS_##v##_WITH_AES_256_CBC_SHA

#define AES_CIPHERS(v)					\
	AES_GCM_CIPHERS(v),				\
	AES_CBC_CIPHERS(v)

static const int default_ciphersuites_server[] =
{
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_ECDSA),
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_RSA),
	AES_CBC_CIPHERS(ECDHE_RSA),
	AES_CIPHERS(RSA),
	0
};

static const int default_ciphersuites_client[] =
{
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_ECDSA),
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_RSA),
	MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(DHE_RSA),
	AES_CBC_CIPHERS(ECDHE_ECDSA),
	AES_CBC_CIPHERS(ECDHE_RSA),
	AES_CBC_CIPHERS(DHE_RSA),
	AES_CIPHERS(RSA),
	0
};


__hidden struct ustream_ssl_ctx *
__ustream_ssl_context_new(bool server)
{
	struct ustream_ssl_ctx *ctx;
	mbedtls_ssl_config *conf;
	int ep;

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

	ep = server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

	mbedtls_ssl_config_defaults(conf, ep, MBEDTLS_SSL_TRANSPORT_STREAM,
				    MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(conf, _random, NULL);

	if (server) {
		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites_server);
		mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3,
					     MBEDTLS_SSL_MINOR_VERSION_3);
	} else {
		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_ciphersuites(conf, default_ciphersuites_client);
	}

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

// mbedtls 3.x made pk_info unexposed so we check it has a type
	if (!mbedtls_pk_get_type(&ctx->key))
		return;

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
// because we striped version info from mbedtls, use a const that removed in mbedtls 3.X
#if defined(MBEDTLS_DHM_RFC5114_MODP_2048_P)
	ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL);
#else
	ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL, _random, NULL);
#endif
	if (ret)
		return -1;

	ustream_ssl_update_own_cert(ctx);
	return 0;
}

__hidden int __ustream_ssl_set_ciphers(struct ustream_ssl_ctx *ctx, const char *ciphers)
{
	int *ciphersuites = NULL, *tmp, id;
	char *cipherstr, *p, *last, c;
	size_t len = 0;

	if (ciphers == NULL)
		return -1;

	cipherstr = strdup(ciphers);

	if (cipherstr == NULL)
		return -1;

	for (p = cipherstr, last = p;; p++) {
		if (*p == ':' || *p == 0) {
			c = *p;
			*p = 0;

			id = mbedtls_ssl_get_ciphersuite_id(last);

			if (id != 0) {
				tmp = realloc(ciphersuites, (len + 2) * sizeof(int));

				if (tmp == NULL) {
					free(ciphersuites);
					free(cipherstr);

					return -1;
				}

				ciphersuites = tmp;
				ciphersuites[len++] = id;
				ciphersuites[len] = 0;
			}

			if (c == 0)
				break;

			last = p + 1;
		}

		/*
		 * mbedTLS expects cipher names with dashes while many sources elsewhere
		 * like the Firefox wiki or Wireshark specify ciphers with underscores,
		 * so simply convert all underscores to dashes to accept both notations.
		 */
		else if (*p == '_') {
			*p = '-';
		}
	}

	free(cipherstr);

	if (len == 0)
		return -1;

	mbedtls_ssl_conf_ciphersuites(&ctx->conf, ciphersuites);
	free(ctx->ciphersuites);

	ctx->ciphersuites = ciphersuites;

	return 0;
}

__hidden int __ustream_ssl_set_require_validation(struct ustream_ssl_ctx *ctx, bool require)
{
	int mode = MBEDTLS_SSL_VERIFY_OPTIONAL;

	if (!require)
		mode = MBEDTLS_SSL_VERIFY_NONE;

	mbedtls_ssl_conf_authmode(&ctx->conf, mode);

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
	free(ctx->ciphersuites);
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
