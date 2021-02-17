//
// Copyright 2021 Dave Voutila <dave@sisu.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>

#include "core/nng_impl.h"
#include <nng/supplemental/tls/engine.h>

struct nng_tls_engine_conn {
	void *              tls;
	struct tls *        ctx;
        struct tls *        server_ctx;
        // XXX: we explicilty link to the config so we can access server_name
        struct nng_tls_engine_config * cfg;
};

struct nng_tls_engine_config {
	struct tls_config * config;
        char *              server_name;
        enum nng_tls_mode   mode;
};


#define CERT_FAIL         "certificate verification"
#define HANDSHAKE_FAIL    "handshake failed"

static int
tls_error_lookup(struct tls *ctx)
{
        const char *err;

        err = tls_error(ctx);
        if (err == NULL) {
                return (0);
        }

        if (nni_strncasecmp(err, CERT_FAIL, strlen(CERT_FAIL)) == 0) {
                return NNG_EPEERAUTH;
        }

        if (nni_strncasecmp(err, HANDSHAKE_FAIL, strlen(HANDSHAKE_FAIL)) == 0) {
                return NNG_EPEERAUTH;
        }
        return (NNG_EINVAL);
}

static ssize_t
net_read(struct tls *ctx, void *buf, size_t buflen, void *cb_arg)
{
        NNI_ARG_UNUSED(ctx);
        void * tls = cb_arg;
        size_t sz = buflen;
        int    rv;

        rv = nng_tls_engine_recv(tls, buf, &sz);
        switch (rv) {
        case 0:
                return ((ssize_t) sz);
        case NNG_EAGAIN:
                return (TLS_WANT_POLLIN);
        default:
                return (-1);
        }
}

static ssize_t
net_send(struct tls *ctx, const void *buf, size_t buflen, void *cb_arg)
{
        NNI_ARG_UNUSED(ctx);
        void * tls = cb_arg;
        size_t sz = buflen;
        int    rv;

        rv = nng_tls_engine_send(tls, buf, &sz);
        switch (rv) {
        case 0:
                return ((ssize_t) sz);
        case NNG_EAGAIN:
                return (TLS_WANT_POLLOUT);
        default:
                return (-1);
        }
}

static void
conn_close(nng_tls_engine_conn *ec)
{
        int rv;

        if (ec->server_ctx != NULL) {
                do {
                        rv = tls_close(ec->server_ctx);
                } while (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT);
        }

        do {
                rv = tls_close(ec->ctx);
        } while (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT);
}

static int
conn_recv(nng_tls_engine_conn *ec, uint8_t *buf, size_t *szp)
{
	ssize_t     sz;
        struct tls *ctx;

        if (ec->server_ctx != NULL) {
                ctx = ec->server_ctx;
        } else {
                ctx = ec->ctx;
        }

        if ((sz = tls_read(ctx, buf, *szp)) < 0) {
                switch (sz) {
                case TLS_WANT_POLLIN:
                case TLS_WANT_POLLOUT:
                        return (NNG_EAGAIN);
                default:
                        // printf("TLS conn_recv error: %s\n", tls_error(ctx));
                        sz = tls_error_lookup(ctx);
                        return (int) sz;
                }
        }
        *szp = (size_t) sz;
	return (0);
}

static int
conn_send(nng_tls_engine_conn *ec, const uint8_t *buf, size_t *szp)
{
	ssize_t     sz;
        struct tls *ctx;

        if (ec->server_ctx != NULL) {
                ctx = ec->server_ctx;
        } else {
                ctx = ec->ctx;
        }

        if ((sz = tls_write(ctx, buf, *szp)) < 0) {
                switch (sz) {
                case TLS_WANT_POLLIN:
                case TLS_WANT_POLLOUT:
                        return (NNG_EAGAIN);
                default:
                        // Cert verification can fail here
                        // printf("TLS conn_send error: %s\n", tls_error(ctx));
                        sz = tls_error_lookup(ctx);
                        return (int) sz;
                }
        }
        *szp = (size_t) sz;
        return (0);
}

// XXX: Explicit calls of tls_handshake(3) are optional with libtls since it
// will auto-handshake on send/recv.
static int
conn_handshake(nng_tls_engine_conn *ec)
{
        int         rv;
        struct tls *ctx;

        if (ec->server_ctx != NULL) {
                ctx = ec->server_ctx;
        } else {
                ctx = ec->ctx;
        }

        rv = tls_handshake(ctx);
        switch (rv) {
        case TLS_WANT_POLLIN:
        case TLS_WANT_POLLOUT:
                return (NNG_EAGAIN);
        case 0:
                return (0);
        default:
                printf("DEBUG(%s): %s\n", __func__, tls_error(ctx));
                return (tls_error_lookup(ctx));
        }
}

// There's no true analog with libtls, but we can check if the peer provided a
// certificate and perform some ad-hoc verification based on our current auth
// mode.
static bool
conn_verified(nng_tls_engine_conn *ec)
{
        struct tls       *ctx;
        time_t            time;
        enum nng_tls_mode mode;
        const char       *name = NULL;

        if (ec->server_ctx != NULL) {
                ctx = ec->server_ctx;
        } else {
                ctx = ec->ctx;
        }

        time = (time_t) nni_clock();

        if (ec->cfg) {
                name = ec->cfg->server_name;
                mode = ec->cfg->mode;
        }


        // Per the man pages, these tls_peer_* functions only succeed after the
        // handshake completes. Otherwise, they return errors.
        if (tls_peer_cert_provided(ctx) == 1) {
                // First, check time
                if (tls_peer_cert_notbefore(ctx) < time
                    && tls_peer_cert_notafter(ctx) < time) {

                        // In server mode, cfg->server_name is NULL
                        if (mode == NNG_TLS_MODE_SERVER) {
                                name = tls_conn_servername(ctx);
                        }

                        if (name &&
                            tls_peer_cert_contains_name(ctx, name) == 1) {
                                return true;
                        }
                        // XXX: we do not check issuer at the moment.
                }
        }

        return false;
}


static int
conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg)
{
        int         rv = 0;
        struct tls *cctx = NULL;

        // Keep a copy of the opaque nng tls pointer and engine config
        ec->tls = tls;
        ec->cfg = cfg;

        // Initialize a new TLS context
        if (cfg->mode == NNG_TLS_MODE_SERVER) {
                ec->ctx = tls_server();
                if (ec->ctx == NULL) {
                        nni_plat_printf("%s: tls_server create failed\n",
                                        __func__);
                        return (-1);
                }
        } else {
                ec->ctx = tls_client();
                if (ec->ctx == NULL ){
                        nni_plat_printf("%s: tls_client create failed\n",
                                        __func__);
                        return (-1);
                }
        }

        // Apply the given configuration. If there are problems with keys or
        // certificates, it might fail here.
        rv = tls_configure(ec->ctx, cfg->config);
        if (rv != 0) {
                printf("DEBUG(%s): tls_configure: '%s'\n", __func__,
                       tls_error(ec->ctx));
                rv = tls_error_lookup(ec->ctx);
                return (rv);
        }

        // Configure the appropriate io callbacks. For a listener, this creates
        // a new/additional TLS context (cctx).
        // TODO: figure out if the original context (ctx) is still required
        if (cfg->mode == NNG_TLS_MODE_SERVER) {
                rv = tls_accept_cbs(ec->ctx, &cctx, net_read, net_send,
                                    ec->tls);
        } else {
                rv = tls_connect_cbs(ec->ctx, net_read, net_send, ec->tls,
                                     cfg->server_name);
        }
        if (rv != 0) {
                return (tls_error_lookup(ec->ctx));
        }

        ec->server_ctx = cctx;
	return (0);
}

static void
conn_fini(nng_tls_engine_conn *ec)
{
        if (ec->server_ctx) {
                tls_free(ec->server_ctx);
        }

	tls_free(ec->ctx);
}

// See https://man.openbsd.org/tls_config_set_protocols.3
static int
config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
        int rv;
	uint32_t versions = TLS_PROTOCOLS_ALL;

        if (min_ver > max_ver) {
                return (NNG_ENOTSUP);
        }

        // TODO: check if NNG_TLS_1_x lines up natively with the
        // TLS_PROTOCOL_TLSv1_x stuff and we can skip this

        switch (min_ver) {
        case NNG_TLS_1_0:
                break;
        case NNG_TLS_1_1:
                versions ^= (TLS_PROTOCOL_TLSv1_0);
                break;
        case NNG_TLS_1_2:
                versions ^= (TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1);
                break;
        case NNG_TLS_1_3:
                versions = TLS_PROTOCOL_TLSv1_3;
                break;
        default:
                return (NNG_ENOTSUP);
        }

        switch (max_ver) {
        case NNG_TLS_1_0:
                versions = TLS_PROTOCOL_TLSv1_0;
                break;
        case NNG_TLS_1_1:
                versions ^= (TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3);
                break;
        case NNG_TLS_1_2:
                versions ^= TLS_PROTOCOL_TLSv1_3;
                break;
        case NNG_TLS_1_3:
                break;
        default:
                return (NNG_ENOTSUP);
        }

        rv = tls_config_set_protocols(cfg->config, versions);
	return (rv);
}

static int
config_auth_mode(nng_tls_engine_config *cfg, nng_tls_auth_mode mode)
{
	switch (mode) {
        case NNG_TLS_AUTH_MODE_NONE:
                tls_config_insecure_noverifycert(cfg->config);
                tls_config_insecure_noverifyname(cfg->config);
                tls_config_insecure_noverifytime(cfg->config);
                return (0);
        case NNG_TLS_AUTH_MODE_OPTIONAL:
                tls_config_verify_client_optional(cfg->config);
                tls_config_insecure_noverifyname(cfg->config);
                return (0);
        case NNG_TLS_AUTH_MODE_REQUIRED:
                tls_config_verify(cfg->config);
                tls_config_verify_client(cfg->config);
                return (0);
        default:
                return (NNG_EINVAL);
        }
}

static int
config_ca_chain(nng_tls_engine_config *cfg, const char *certs, const char *crl)
{
        size_t         len;
        const uint8_t *pem;
        int            rv;

        // Certs and CRL are already in memory, NUL-terminated.
        pem = (const uint8_t *) certs;
        len = strlen(certs);

        if ((rv = tls_config_set_ca_mem(cfg->config, pem, len)) != 0) {
                printf("DEBUG(%s): tls_config_set_ca_mem: '%s'\n", __func__,
                       tls_config_error(cfg->config));
                return (rv);
        }
        if (crl != NULL) {
                pem = (const uint8_t *) crl;
                len = strlen(crl);
                if ((rv = tls_config_set_crl_mem(cfg->config, pem, len)) != 0) {
                        return (rv);
                }
        }

        // TODO: does libtls support setting the CA chain to just the provided
        // pem and crl? Is that even sane?

	return (0);
}

static int
config_own_cert(nng_tls_engine_config *cfg, const char *cert, const char *key,
    const char *pass)
{
        NNI_ARG_UNUSED(pass);
        size_t         clen;
        size_t         klen;
        int            rv;

        // XXX: for now, we don't support encrypted keys as libtls needs to do
        // the file loading if we're going to support it :-(

        clen = strlen(cert) + 1;
        klen = strlen(key) + 1;

        rv = tls_config_set_keypair_mem(cfg->config,
                                        (uint8_t *) cert, clen,
                                        (uint8_t *) key, klen);
        if (rv != 0) {
                printf("DEBUG(%s): %s\n", __func__, tls_config_error(cfg->config));
                return (rv);
        }

	return (0);
}

static int
config_server_name(nng_tls_engine_config *cfg, const char *name)
{
	// via mbeldtls/tls.c
        char *dup;
	if ((dup = strdup(name)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (cfg->server_name) {
		nni_strfree(cfg->server_name);
	}
	cfg->server_name = dup;
	return (0);
}

static int
config_init(nng_tls_engine_config *cfg, enum nng_tls_mode mode)
{
        int rv;

        cfg->config = tls_config_new();
        cfg->mode = mode;

        if (mode == NNG_TLS_MODE_SERVER) {
                rv = config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);
        } else {
                rv = config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);
        }

        return (rv);
}

static void
config_fini(nng_tls_engine_config *cfg)
{
        if (cfg->server_name) {
                nni_strfree(cfg->server_name);
        }
        tls_config_free(cfg->config);
}

static nng_tls_engine_config_ops config_ops = {
	.init     = config_init,
	.fini     = config_fini,
	.size     = sizeof(nng_tls_engine_config),
	.auth     = config_auth_mode,
	.ca_chain = config_ca_chain,
	.own_cert = config_own_cert,
	.server   = config_server_name,
	.version  = config_version,
};

static nng_tls_engine_conn_ops conn_ops = {
	.size      = sizeof(nng_tls_engine_conn),
	.init      = conn_init,
	.fini      = conn_fini,
	.close     = conn_close,
	.recv      = conn_recv,
	.send      = conn_send,
	.handshake = conn_handshake,
	.verified  = conn_verified,
};

static nng_tls_engine tls_engine_libtls = {
	.version     = NNG_TLS_ENGINE_VERSION,
	.config_ops  = &config_ops,
	.conn_ops    = &conn_ops,
	.name        = "libtls",
	.description = "LibreSSL via libtls",
	.fips_mode   = false,
};

int
nng_tls_engine_init_libtls(void)
{
        int rv;

        rv = nng_tls_engine_register(&tls_engine_libtls);
        return (rv);
}

void
nng_tls_engine_fini_libtls(void)
{
        // nop
}
