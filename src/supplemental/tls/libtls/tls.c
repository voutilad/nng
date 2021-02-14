#include <string.h>
#include <tls.h>

#include "core/nng_impl.h"
#include <nng/supplemental/tls/engine.h>

struct nng_tls_engine_conn {
	void *              tls;
	struct tls *        ctx;
};

struct nng_tls_engine_config {
	struct tls_config * config;
        char *              server_name;
};

static int
config_init()
{
        // TODO
	return -1;
}

static void
config_fini(nng_tls_engine_config *cfg)
{
        // TODO
}

static void
conn_fini(nng_tls_engine_conn *ec)
{
	tls_free(ec->ctx);
}

static int
conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg)
{
	// TODO: initialize config? or client?
	return -1;
}

static void
conn_close(nng_tls_engine_conn *ec)
{
	// TODO
}

static int
conn_recv()
{
	// TODO
	return -1;
}

static int
conn_send()
{
	// TODO
	return -1;
}

static int
conn_handshake()
{
	// TODO
	return -1;
}

static bool
conn_verified(nng_tls_engine_conn *ec)
{
	// TODO
	return -1;
}

static int
config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
	// TODO
	return -1;
}

static int
config_auth_mode()
{
	// TODO
	return -1;
}

static int
config_ca_chain()
{
	// TODO
	return -1;
}

static int
config_own_cert()
{
	// TODO
	return -1;
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
        // TODO
}
