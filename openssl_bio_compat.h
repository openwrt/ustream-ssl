#ifndef OPENSSL_BIO_COMPAT_H
#define OPENSSL_BIO_COMPAT_H

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/bio.h>
#include <string.h>

#define BIO_get_data(b) (b->ptr)
#define BIO_set_data(b, v) (b->ptr = v)
#define BIO_set_init(b, v) (b->init = v)
#define BIO_meth_set_write(m, f) (m->bwrite = f)
#define BIO_meth_set_read(m, f) (m->bread = f)
#define BIO_meth_set_puts(m, f) (m->bputs = f)
#define BIO_meth_set_gets(m, f) (m->bgets = f)
#define BIO_meth_set_ctrl(m, f) (m->ctrl = f)
#define BIO_meth_set_create(m, f) (m->create = f)
#define BIO_meth_set_destroy(m, f) (m->destroy = f)

static inline BIO_METHOD *BIO_meth_new(int type, const char *name)
{
	BIO_METHOD *bm = calloc(1, sizeof(BIO_METHOD));
	if (bm) {
		bm->type = type;
		bm->name = name;
	}
	return bm;
}

#endif /* OPENSSL_VERSION_NUMBER */

#endif /* OPENSSL_BIO_COMPAT_H */
