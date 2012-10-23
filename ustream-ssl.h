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

void *ustream_ssl_context_new(bool server);
int ustream_ssl_context_set_crt_file(void *ctx, const char *file);
int ustream_ssl_context_set_key_file(void *ctx, const char *file);
void ustream_ssl_context_free(void *ctx);

int ustream_ssl_init(struct ustream_ssl *us, struct ustream *conn, void *ctx, bool server);

#endif
