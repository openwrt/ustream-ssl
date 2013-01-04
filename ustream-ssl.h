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
