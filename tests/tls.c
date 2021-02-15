//
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// TLS tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/transport/tls/tls.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

// These keys are for demonstration purposes ONLY.  DO NOT USE.
// The certificate is valid for 100 years, because I don't want to
// have to regenerate it ever again. The CN is 127.0.0.1, and self-signed.
//
// Generated using openssl:
//
// % openssl ecparam -name secp224r1 -genkey -out  key.key
// % openssl req -new -key key.key -out cert.csr -sha256
// % openssl x509 -req -in cert.csr -days 36500 -out cert.crt
//    -signkey key.key -sha256
//
// Secp224r1 chosen as a least common denominator recommended by NIST-800.
//
//

// DV: had to temporarily swap out the cert and private key here for now
// as the EC keys were not working with libtls

/*
static const char cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBzDCCAXkCCQCNJMf8eYUHxTAKBggqhkjOPQQDAjB2MQswCQYDVQQGEwJVUzEL\n"
    "MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBEaWVnbzEUMBIGA1UECgwLbmFub21z\n"
    "Zy5vcmcxHDAaBgNVBAsME1NhbXBsZSBDZXJ0aWZpY2F0ZXMxEjAQBgNVBAMMCWxv\n"
    "Y2FsaG9zdDAgFw0yMDAyMjMxODMwMDZaGA8yMTIwMDEzMDE4MzAwNlowdjELMAkG\n"
    "A1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTYW4gRGllZ28xFDASBgNV\n"
    "BAoMC25hbm9tc2cub3JnMRwwGgYDVQQLDBNTYW1wbGUgQ2VydGlmaWNhdGVzMRIw\n"
    "EAYDVQQDDAlsb2NhbGhvc3QwTjAQBgcqhkjOPQIBBgUrgQQAIQM6AAS9hA5gYo10\n"
    "jx+gzJdzYbxHzigJYXawdHtyoAud/TT/dUCt0ycpOzTMiO3CoDNxep+/mkmgxjfp\n"
    "ujAKBggqhkjOPQQDAgNBADA+Ah0A9b+GcfbhzzmI2NcYb4auE6XTYJPkPzHt6Adi\n"
    "fwIdAMJO2LEr6WHH6JGLlishVqjF78TtkuB5t+kzneQ=\n"
    "-----END CERTIFICATE-----\n";

static const char key[] =
    "-----BEGIN EC PARAMETERS-----\n"
    "gUrgQQAIQ==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MGgCAQEEHChK068x8MWcBzhpO7qANvW4iTo7E0yzMYFXGn+gBwYFK4EEACGhPAM6\n"
    "AAS9hA5gYo10jx+gzJdzYbxHzigJYXawdHtyoAud/TT/dUCt0ycpOzTMiO3CoDNx\n"
    "ep+/mkmgxjfpug==\n"
    "-----END EC PRIVATE KEY-----\n";
*/

static const char key[] =
        "-----BEGIN PRIVATE KEY-----\n"
"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\n"
"4obuRSC9j9h/joxOIOeWHr7mDgaMeI4=\n"
"-----END PRIVATE KEY-----\n";


static const char cert[] =
        "-----BEGIN CERTIFICATE-----\n"
"MIIEpDCCAowCCQCnfOdK3qDIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
"b2NhbGhvc3QwHhcNMjEwMjE0MTQwMTU2WhcNMjEwMzE2MTQwMTU2WjAUMRIwEAYD\n"
"VQQDDAlsb2NhbGhvc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCb\n"
"TzGn6wiOWogyewD+5XJMkYvdKWaD6msDdJKlX9arfIOu/3FcmFh9Q+bzyTSfanWq\n"
"nh20UoSAO5f4BtH/XBI+CN6DAfXjq6ylvVcYfp4evmeHoOdx3S2qQvJbdotP1Wdf\n"
"sUmy3cyTAN87bb1akyjqp+naEbF75A0/p6g1S94+X25pd8WnRMhdwga91kRwA9jm\n"
"lllgzc9cEPdjL9gbjc75Wzgjr+T3EdKCv+hriKsUvSUKXLu86q8bM75M0KDFtBkj\n"
"tmj4D8HlKbjTkW/VFTXZzDaopUOqPMFmLJW7XJmXln/pJIADEIzECcFhzcZkWk5g\n"
"P2kFT8gzGgZvHiEsommt1tROxkaMX/GbR/B/1rS298m4uxn88fV0GlbGbCjo/+XD\n"
"E8mcyQ9gsGsaNO34eorfKuxcq/JJaRlD8eOB5JD0rMoPNbfwEz41uPnGlD4ZAXw3\n"
"mk/brbTDg68KUCLK9Xw5ucZTAgEEPVJ3LsKVs/NC+6inTCdoTLblHxHA4NvkjI5b\n"
"XZH3Lv8wKBcQEwgLV99mriDrscsJBYldGfjwvb5Crsan3YhOTpg+DuMI+zirQQU7\n"
"8Xz2BemjzQviAia9blIPLg4FhF/Nn7Ns9XJp83wp3Kq7ZN9xQ0CNWhkn/eGsj4uv\n"
"oiLowpQku6WdPUMOzAZtsgoKNJum4Ur1cycdW1pOfQIDAQABMA0GCSqGSIb3DQEB\n"
"CwUAA4ICAQB7+HDxttX+iatVeIR9xQnqJIDlt1eOTqXD72jLrVsokE/kNwrGSfeK\n"
"OUtWbUCETfjMAzGnLC2/yFq6AzS+puCKVZj6e7wFz7FPr27VOZBMZQGVUy6QidyJ\n"
"RLIuga56QD3fuZ/cESxTOjoM1SXuxTzkbU4BzZCQHBE2hTmISGDxqibxKpXP+auL\n"
"M/izQxZ5fUajetB/s4RD84GVjULVQTbP+BOTeUeBqa8Uui7FVdASFvk2S7J+nuXw\n"
"1d3FPp3i0LzBwHxpfzW+jsGVqaHsLQB9srERVWiwnCdxZWsoXk/1yqnw+ZC40hwV\n"
"0tGortkP+UdjHhhABbfNe/ki/jh5t9Z7m2cqr5c1Lgd4ZWsOl//dkvkIYrDihnfY\n"
"LNT4ATDGLMeAGU6IX8Lo1cjf4ZPTGVLwav7qRikaGTlXyPaKoG/wlmgr4HT+LWnr\n"
"eI1KzIBPmZiEP9UF9qwjk4eq7/1dCyN2CkPhBs+Pfhc3187Lu1kDzGOAwKCAfabD\n"
"BilZKj1TIpi0iRX2Ntixj38F0fd/016jcLOXKHLdqz4bXMqqmsggGQrwBZFy5151\n"
"QRePTFtuwNy5cKiwyS5vA12sP8NZCaRPhonzaCbPHYQHTkum6GlaHPLpNSf8tCDU\n"
"/y9aAK55AqFz0cadHRFa2KyoF5VYPga6HN9EDY/UPqSdo8nigMIoww==\n"
        "-----END CERTIFICATE-----\n";



static int
check_props_v4(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	bool         b;
	nng_sockaddr la;
	nng_sockaddr ra;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);

	// Typed access
	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_INET);
	So(la.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_in.sa_port != 0);
	So(la.s_in.sa_addr == htonl(0x7f000001));

	// Untyped access
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET);
	So(ra.s_in.sa_port != 0);
	So(ra.s_in.sa_addr == htonl(0x7f000001));

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_KEEPALIVE, &b) == 0);
	So(b == false); // default

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_NODELAY, &b) == 0);
	So(b == true); // default

	// Check for type enforcement
	int i;
	So(nng_pipe_getopt_int(p, NNG_OPT_REMADDR, &i) == NNG_EBADTYPE);

	z = 1;
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

	return (0);
}

static int
init_dialer_tls_ex(nng_dialer d, bool own_cert)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
		goto out;
	}

	if ((rv = nng_tls_config_server_name(cfg, "localhost")) != 0) {
		goto out;
	}
	nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);

	if (own_cert) {
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, NULL)) !=
		    0) {
			goto out;
		}
	}

	rv = nng_dialer_setopt_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

static int
init_dialer_tls(nng_dialer d)
{
	return (init_dialer_tls_ex(d, false));
}

static int
init_listener_tls_ex(nng_listener l, int auth_mode)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER)) != 0) {
		return (rv);
	}
	if ((rv = nng_tls_config_own_cert(cfg, cert, key, NULL)) != 0) {
		goto out;
	}
	if ((rv = nng_listener_setopt_ptr(l, NNG_OPT_TLS_CONFIG, cfg)) != 0) {
		goto out;
	}
	switch (auth_mode) {
	case NNG_TLS_AUTH_MODE_REQUIRED:
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
			goto out;
		}
		break;
	default:
		break;
	}
	if ((rv = nng_tls_config_auth_mode(cfg, auth_mode)) != 0) {
		goto out;
	}
out:
	nng_tls_config_free(cfg);
	return (0);
}

static int
init_listener_tls(nng_listener l)
{
	return (init_listener_tls_ex(l, NNG_TLS_AUTH_MODE_NONE));
}

static int
init_dialer_tls_file(nng_dialer d)
{
	int   rv;
	char *tmpdir;
	char *pth;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((pth = nni_file_join(tmpdir, "tls_test_cacert.pem")) == NULL) {
		nni_strfree(tmpdir);
		return (NNG_ENOMEM);
	}
	nni_strfree(tmpdir);

	if ((rv = nni_file_put(pth, cert, strlen(cert))) != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nng_dialer_setopt_string(d, NNG_OPT_TLS_CA_FILE, pth);
	nni_file_delete(pth);
	nni_strfree(pth);

	return (rv);
}

static int
init_listener_tls_file(nng_listener l)
{
	int   rv;
	char *tmpdir;
	char *pth;
	char *certkey;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}

	if ((pth = nni_file_join(tmpdir, "tls_test_certkey.pem")) == NULL) {
		nni_strfree(tmpdir);
		return (NNG_ENOMEM);
	}
	nni_strfree(tmpdir);

	if ((rv = nni_asprintf(&certkey, "%s\r\n%s\r\n", cert, key)) != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nni_file_put(pth, certkey, strlen(certkey));
	nni_strfree(certkey);
	if (rv != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nng_listener_setopt_string(l, NNG_OPT_TLS_CERT_KEY_FILE, pth);
	if (rv != 0) {
		// We can wind up with EBUSY from the server already
		// running.
		if (rv == NNG_EBUSY) {
			rv = 0;
		}
	}

	nni_file_delete(pth);
	nni_strfree(pth);
	return (rv);
}

TestMain("TLS Transport", {
	static trantest tt;

	if (strcmp(nng_tls_engine_name(), "none") == 0) {
		Skip("TLS not enabled");
	}

	tt.dialer_init   = init_dialer_tls;
	tt.listener_init = init_listener_tls;
	tt.tmpl          = "tls+tcp://127.0.0.1:%u";
	tt.proptest      = check_props_v4;

	trantest_test(&tt);

	Convey("We can register the TLS transport",
	    { So(nng_tls_register() == 0); });

	Convey("We cannot connect to wild cards", {
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_dial(s, addr, NULL, 0) == NNG_EADDRINVAL);
	});

	Convey("We can bind to wild card", {
		nng_socket   s1;
		nng_socket   s2;
		char         addr[NNG_MAXADDRLEN];
		nng_listener l;
		nng_dialer   d;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls(l) == 0);
		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_setopt_int(
		       d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
		So(nng_listener_start(l, 0) == 0);
		So(nng_dialer_start(d, 0) == 0);
	});

	SkipConvey("We can bind to port zero", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char *       addr;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		So(nng_listener_create(&l, s1, "tls+tcp://127.0.0.1:0") == 0);
		So(init_listener_tls(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		So(nng_listener_getopt_string(l, NNG_OPT_URL, &addr) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_setopt_int(
		       d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_strfree(addr);
	});

	Convey("Malformed TLS addresses do not panic", {
		nng_socket s1;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });

		// Note that if we listen to an unspecified port, then we
		// get a random port.  So we don't look at that.  This allows
		// a user to obtain a port at random and then query to see
		// which one was chosen.

		So(nng_dial(s1, "tls+tcp://127.0.0.1", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tls+tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tls+tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls+tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls+tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	Convey("We can use local interface to connect", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char         addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		// reset port back one
		trantest_prev_address(
		    addr, "tls+tcp://127.0.0.1;127.0.0.1:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_start(d, 0) == 0);
	});

	Convey("Botched local interfaces fail reasonably", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://1x.2;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	Convey("Can't specify address that isn't ours", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://8.8.8.8;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	// We really need to have pipe start/negotiate as one of the key steps
	// during connect establish.  Until that happens, we cannot verify the
	// peer. See bug #208.
	SkipConvey("Verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		size_t       sz;
		char         addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_file(NULL, l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_setopt_int(s2, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_REQUIRED) == 0);

		So(nng_dial(s2, addr, NULL, 0) == NNG_EPEERAUTH);
	});

	Convey("No verify works", {
		nng_socket   s1; // server
		nng_socket   s2; // client
		nng_listener l;
		char         addr[NNG_MAXADDRLEN];
		nng_msg *    msg;
		nng_pipe     p;
		bool         b;
		nng_dialer   d;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_file(l) == 0);
		So(nng_listener_setopt_int(l, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_OPTIONAL) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_file(d) == 0);
		So(nng_dialer_setopt_string(
		       d, NNG_OPT_TLS_SERVER_NAME, "localhost") == 0);
		So(nng_dialer_start(d, 0) == 0);

		So(nng_send(s2, "hello", 6, 0) == 0);
		So(nng_recvmsg(s1, &msg, 0) == 0);
		So(msg != NULL);
		So(nng_msg_len(msg) == 6);
		So(strcmp(nng_msg_body(msg), "hello") == 0);
		p = nng_msg_get_pipe(msg);
		So(nng_pipe_id(p) > 0);
		So(nng_pipe_getopt_bool(p, NNG_OPT_TLS_VERIFIED, &b) == 0);
		So(b == false);
		nng_msg_free(msg);
	});

	Convey("Valid verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char         addr[NNG_MAXADDRLEN];
		nng_msg *    msg;
		nng_pipe     p;
		bool         b;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp4://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_ex(l, NNG_TLS_AUTH_MODE_REQUIRED) == 0);
		So(nng_listener_start(l, 0) == 0);

		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp4://localhost:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_ex(d, true) == 0);

		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_msleep(100);

		// send from the server to the client-- the client always
		// verifies the server.
		So(nng_send(s2, "hello", 6, 0) == 0);
		So(nng_recvmsg(s1, &msg, 0) == 0);
		So(msg != NULL);
		So(nng_msg_len(msg) == 6);
		So(strcmp(nng_msg_body(msg), "hello") == 0);
		p = nng_msg_get_pipe(msg);
		So(nng_pipe_id(p) > 0);
		So(nng_pipe_getopt_bool(p, NNG_OPT_TLS_VERIFIED, &b) == 0);
		So(b == true);
		int i;
		So(nng_pipe_getopt_int(p, NNG_OPT_TLS_VERIFIED, &i) ==
		    NNG_EBADTYPE);
		nng_msg_free(msg);
	});

	Convey("No delay option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_NODELAY, &x) ==
		    NNG_EBADTYPE);
		x = 0;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_dialer_setopt(d, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) ==
		    NNG_EINVAL);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		x = 0;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_listener_setopt(
		       l, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) == NNG_EINVAL);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, true) == 0);
		v = false;
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
	});

	Convey("Keepalive option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_KEEPALIVE, true) ==
		    0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_KEEPALIVE, &x) ==
		    NNG_EBADTYPE);
		x = 1;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_KEEPALIVE, &v) ==
		    0);
		So(v == false);
		x = 1;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, false) == 0);
		v = true;
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, true) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
	});
})
