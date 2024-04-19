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
#include <psa/crypto.h>
#include <mbedtls/debug.h>

static void debug_cb(void *ctx_p, int level,
                     const char *file, int line,
                     const char *str)
{
	struct ustream_ssl_ctx *ctx = ctx_p;
	const char *fstr;
	char buf[512];
	int len;

	if (!ctx->debug_cb)
		return;

	while ((fstr = strstr(file + 1, "library/")) != NULL)
		file = fstr;

	len = snprintf(buf, sizeof(buf), "%s:%04d: %s", file, line, str);
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;
	if (buf[len - 1] == '\n')
		buf[len - 1] = 0;
	ctx->debug_cb(ctx->debug_cb_priv, level, buf);
}

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

static int s_fd_read(void *ctx, unsigned char *buf, size_t len)
{
	struct uloop_fd *ufd = ctx;
	mbedtls_net_context net = {
		.fd = ufd->fd
	};

	return mbedtls_net_recv(&net, buf, len);
}

static int s_fd_write(void *ctx, const unsigned char *buf, size_t len)
{
	struct uloop_fd *ufd = ctx;
	mbedtls_net_context net = {
		.fd = ufd->fd
	};

	return mbedtls_net_send(&net, buf, len);
}

__hidden void ustream_set_io(struct ustream_ssl *us)
{
	if (us->conn)
		mbedtls_ssl_set_bio(us->ssl, us->conn, s_ustream_write, s_ustream_read, NULL);
	else
		mbedtls_ssl_set_bio(us->ssl, &us->fd, s_fd_write, s_fd_read, NULL);
}

static int _random(void *ctx, unsigned char *out, size_t len)
{
#ifdef linux
	if (getrandom(out, len, 0) != (ssize_t) len)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
#else
	static FILE *f;

	if (!f)
		f = fopen("/dev/urandom", "r");
	if (fread(out, len, 1, f) != 1)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
#endif

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
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256,
#endif

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
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256,
#endif

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_ECDSA),
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(ECDHE_RSA),
	MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	AES_GCM_CIPHERS(DHE_RSA),
	AES_CBC_CIPHERS(ECDHE_ECDSA),
	AES_CBC_CIPHERS(ECDHE_RSA),
	AES_CBC_CIPHERS(DHE_RSA),
/* Removed in Mbed TLS 3.0.0 */
#ifdef MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
#endif
	AES_CIPHERS(RSA),
/* Removed in Mbed TLS 3.0.0 */
#ifdef MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA
	MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
#endif
	0
};


__hidden struct ustream_ssl_ctx *
__ustream_ssl_context_new(bool server)
{
	struct ustream_ssl_ctx *ctx;
	mbedtls_ssl_config *conf;
	int ep;

#ifdef MBEDTLS_PSA_CRYPTO_C
	static bool psa_init;

	if (!psa_init && !psa_crypto_init())
		psa_init = true;
#endif

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

	if (mbedtls_pk_get_type(&ctx->key) == MBEDTLS_PK_NONE)
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

#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
	ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL, _random, NULL);
#else
	ret = mbedtls_pk_parse_keyfile(&ctx->key, file, NULL);
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

	/* force TLS 1.2 when not requiring validation for now */
	if (!require && !ctx->server)
		mbedtls_ssl_conf_max_version(&ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
					     MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_authmode(&ctx->conf, mode);

	return 0;
}

__hidden void __ustream_ssl_context_free(struct ustream_ssl_ctx *ctx)
{
	free(ctx->session_data);
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

#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
static void
__ustream_ssl_save_session(struct ustream_ssl *us)
{
	struct ustream_ssl_ctx *ctx = us->ctx;
	mbedtls_ssl_session sess;

	if (ctx->server)
		return;

	free(ctx->session_data);
	ctx->session_data = NULL;

	mbedtls_ssl_session_init(&sess);
	if (mbedtls_ssl_get_session(us->ssl, &sess) != 0)
		return;

	mbedtls_ssl_session_save(&sess, NULL, 0, &ctx->session_data_len);
	ctx->session_data = malloc(ctx->session_data_len);
	if (mbedtls_ssl_session_save(&sess, ctx->session_data, ctx->session_data_len,
				     &ctx->session_data_len))
		ctx->session_data_len = 0;
	mbedtls_ssl_session_free(&sess);
}
#endif

static int ssl_check_return(struct ustream_ssl *us, int ret)
{
	switch(ret) {
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return U_SSL_PENDING;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
	case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
		__ustream_ssl_save_session(us);
		return U_SSL_RETRY;
#endif
#ifdef MBEDTLS_ECP_RESTARTABLE
	case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
		return U_SSL_RETRY;
#endif
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
	case MBEDTLS_ERR_NET_CONN_RESET:
		return 0;
	default:
		ustream_ssl_error(us, ret);
		return U_SSL_ERROR;
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

	do {
		r = mbedtls_ssl_handshake(ssl);
		if (r == 0) {
			ustream_ssl_verify_cert(us);
			return U_SSL_OK;
		}

		r = ssl_check_return(us, r);
	} while (r == U_SSL_RETRY);

	return r;
}

__hidden int __ustream_ssl_write(struct ustream_ssl *us, const char *buf, int len)
{
	void *ssl = us->ssl;
	int done = 0, ret = 0;

	while (done != len) {
		ret = mbedtls_ssl_write(ssl, (const unsigned char *) buf + done, len - done);
		if (ret < 0) {
			ret = ssl_check_return(us, ret);
			if (ret == U_SSL_RETRY)
				continue;

			if (ret == U_SSL_PENDING)
				return done;

			return -1;
		}

		done += ret;
	}

	return done;
}

__hidden int __ustream_ssl_read(struct ustream_ssl *us, char *buf, int len)
{
	int ret;

	do {
		ret = mbedtls_ssl_read(us->ssl, (unsigned char *) buf, len);
		if (ret >= 0)
			return ret;

		ret = ssl_check_return(us, ret);
	} while (ret == U_SSL_RETRY);

	return ret;
}

__hidden void __ustream_ssl_set_debug(struct ustream_ssl_ctx *ctx, int level,
				      ustream_ssl_debug_cb cb, void *cb_priv)
{
	ctx->debug_cb = cb;
	ctx->debug_cb_priv = cb_priv;
	mbedtls_ssl_conf_dbg(&ctx->conf, debug_cb, ctx);
#ifdef MBEDTLS_DEBUG_C
	mbedtls_debug_set_threshold(level);
#endif
}

__hidden void *__ustream_ssl_session_new(struct ustream_ssl_ctx *ctx)
{
	mbedtls_ssl_context *ssl;
	mbedtls_ssl_session sess;

	ssl = calloc(1, sizeof(*ssl));
	if (!ssl)
		return NULL;

	mbedtls_ssl_init(ssl);

	if (mbedtls_ssl_setup(ssl, &ctx->conf)) {
		free(ssl);
		return NULL;
	}

	if (!ctx->session_data_len)
		return ssl;

	mbedtls_ssl_session_init(&sess);
	if (mbedtls_ssl_session_load(&sess, ctx->session_data, ctx->session_data_len) == 0)
		mbedtls_ssl_set_session(ssl, &sess);

	return ssl;
}

__hidden void __ustream_ssl_session_free(struct ustream_ssl *us)
{
	mbedtls_ssl_free(us->ssl);
	free(us->ssl);
}
