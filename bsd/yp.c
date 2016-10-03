#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <netdb.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/param.h>

#include <ypclnt.h>
#include <rpcsvc/yp.h>

typedef struct yp_context {
	char	*domain;
	char	*server;
	CLIENT	*client;
	int	socket;
	uint16_t	local_port;	// Network byte order
	struct sockaddr_storage	server_sockaddr;
} yp_context_t;

/*
 * Does the grunt work of talking to ypbind on localhost.
 */

static int
_do_ypbind(const char *domain, struct sockaddr_storage *ss)
{
	struct sockaddr_in ypbind_sin = { 0 };
	int client_sock = RPC_ANYSOCK;
	int rv;
	struct ypbind_resp bind_response = { 0 };
	CLIENT *ypbind_client = NULL;
	struct timeval tv = { .tv_sec = 5, };
	ypbind_sin.sin_family = AF_INET;	// Only IPv4 for now?
	ypbind_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	
	ypbind_client = clnttcp_create(&ypbind_sin,
				       YPBINDPROG, YPBINDVERS, &client_sock,
				       0, 0);
	if (ypbind_client == NULL) {
		switch (rpc_createerr.cf_stat) {
		case RPC_PROGNOTREGISTERED:
			warnx("ypbind program not registered on localhost");
			rv = -1;
			errno = ECONNREFUSED;
			break;
		case RPC_SYSTEMERROR:
			warnx("System error while trying to connect to ypbind");
			rv = -1;
			errno = EAGAIN;
			break;
		default:
			rv = -1;
			errno = ECONNREFUSED;
		}
		return rv;
	}
	if (ntohs(ypbind_sin.sin_port) >= IPPORT_RESERVED) {
		if (ypbind_client)
			clnt_destroy(ypbind_client);
		errno = EPERM;
		return -1;
	}
	rv = clnt_call(ypbind_client,
		       YPBINDPROC_DOMAIN,
		       (xdrproc_t)xdr_domainname, &domain,
		       (xdrproc_t)xdr_ypbind_resp, &bind_response, tv);
	clnt_destroy(ypbind_client);
	if (rv != RPC_SUCCESS) {
		if (rv == RPC_PROGUNAVAIL || rv == RPC_PROCUNAVAIL) {
			errno = ECONNREFUSED;
			return -1;
		}
		warnx("ypbind for domain %s not responding", domain);
		errno = ETIMEDOUT;
		return -1;
	}
	/*
	 * Okay, at this point, bind_response has the information we need.
	 */
	bzero(&ypbind_sin, sizeof(ypbind_sin));
	ypbind_sin.sin_family = AF_INET;	// Still only IPv6
	bcopy(&bind_response.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
	      &ypbind_sin.sin_addr.s_addr,
	      sizeof(ypbind_sin.sin_addr.s_addr));
	bcopy(&bind_response.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
	      &ypbind_sin.sin_port,
	      sizeof(ypbind_sin.sin_port));
	bcopy(&ypbind_sin, ss, sizeof(ypbind_sin));
	return 0;
	
}

/*
 * Given the sockaddr, attempt to create an RPC client for YP.
 * It also binds it to a socket, for later checking.
 */
static CLIENT *
yp_client_create(struct sockaddr_storage *ss, int *sock, uint16_t *port)
{
	CLIENT *retval = NULL;
	struct sockaddr_storage client = { 0 };
	*sock = RPC_ANYSOCK;
	struct timeval tv = { .tv_sec = 5, };
	
	// Buffer size values taken directly from libc/yp/yplib.c
	retval = clntudp_bufcreate((void*)ss,
				   YPPROG, YPVERS, tv,
				   sock, 1280, 2304);
	if (retval) {
		socklen_t client_len = ss->ss_len;
		(void)fcntl(*sock, F_SETFD, 1);
		// I'll admit I don't understand how this can work
		(void)bind(*sock, (struct sockaddr*)&client, ss->ss_len);
		client.ss_family = AF_INET;	// Still IPv4 only?
		if (getsockname(*sock, (struct sockaddr*)&client, &client_len) == -1) {
			clnt_destroy(retval);
			retval = NULL;
		} else {
			if (client.ss_family == AF_INET) {
				*port = ((struct sockaddr_in*)&client)->sin_port;
			} else if (client.ss_family == AF_INET6) {
				*port = ((struct sockaddr_in6*)&client)->sin6_port;
			} else {
				clnt_destroy(retval);
				retval = NULL;
			}
		}
		tv.tv_sec = 1;
		clnt_control(retval, CLSET_RETRY_TIMEOUT, (char*)&tv);
	}
	return retval;
}

static int
check_yp_client(yp_context_t *ctx)
{
	struct sockaddr_storage check = { 0 };
	socklen_t checklen = sizeof(check);
	int rv;

#define PORT_EQ(ss1, ss2) \
	(ss1.ss_family == AF_INET ?					\
	  (((struct sockaddr_in*)&ss1)->sin_port == ((struct sockaddr_in*)&ss2)->sin_port) : \
	 (((struct sockaddr_in6*)&ss1)->sin6_port == ((struct sockaddr_in6*)&ss2)->sin6_port))
	
	check.ss_family = ctx->server_sockaddr.ss_family;
	if (getsockname(ctx->socket, (struct sockaddr*)&check, &checklen) == -1 ||
	    check.ss_family != ctx->server_sockaddr.ss_family ||
	    (check.ss_family != AF_INET && check.ss_family != AF_INET6) ||
	    !PORT_EQ(check, ctx->server_sockaddr)) {
		return 0;
	}
	return 1;
}

void *
yp_init(const char *domain, const char *server)
{
	void *retval = NULL;
	yp_context_t *context = NULL;
	struct sockaddr_storage ss = { 0 };
	char default_domain[MAXHOSTNAMELEN] = { 0 };
	const char *server_name = NULL;
	CLIENT *yp_client = NULL;
	int client_sock = RPC_ANYSOCK;
	int local_sock = -1;
	uint16_t local_port = -1;
	
	int rv = -1;
	
	if (domain == NULL) {
		rv = getdomainname(default_domain, sizeof(default_domain));
		if (rv == -1)
			goto done;
		if (default_domain[0] == 0) {
			errno = ENOENT;
			rv = -1;
			goto done;
		}
		domain = default_domain;
	}
	if (server == NULL) {
		rv = _do_ypbind(domain, &ss);
		if (rv == -1) {
			goto done;
		}
	} else {
		struct addrinfo *ai, pai = { 0 };
		pai.ai_family = AF_INET;
		pai.ai_flags = AI_NUMERICSERV;
		
		rv = getaddrinfo(server, "0", &pai, &ai);
		if (rv == -1)
			goto done;
		// Yes, we only use one address; it's possible this should change
		bcopy(ai->ai_addr, &ss, ai->ai_addrlen);
		freeaddrinfo(ai);
		server_name = server;
	}
	/*
	 * At this point, we have a domain, a server address, and (optionally)
	 * a server name.  Let's see if we can get a UDP CLIENT from it.
	 */
	yp_client = yp_client_create(&ss, &local_sock, &local_port);

	if (yp_client) {
		// Okay, let's do the magic
		context = calloc(1, sizeof(*retval));
		if (context == NULL) {
			clnt_destroy(yp_client);
		} else {
			context->domain = strdup(domain);
			context->server = server ? strdup(server) : NULL;
			context->client = yp_client;
			context->socket = local_sock;
			context->local_port = local_port;
			context->server_sockaddr = ss;
			retval = (void*)context;
		}
	} else {
		warn("Could not connect to server");
	}
done:
	return retval;
}

void
yp_close(void *ctx)
{
	yp_context_t *context = ctx;

	if (context->domain)
		free(context->domain);
	if (context->server)
		free(context->server);
	if (context->client)
		clnt_destroy(context->client);
	free(ctx);
}

int
yp_match_r(void *ctx,
	   const char *inmap,
	   const char *inkey, size_t inkeylen,
	   const char **outval, size_t *outvallen)
{
	yp_context_t *context = ctx;
        struct ypresp_val yprv = { 0 };
	struct timeval tv = { .tv_sec = 5, };
	struct ypreq_key yprk;
	int rv;
	
	if (ctx == NULL)
		return (EINVAL);

	if (inkey == NULL || strlen(inkey) == 0 || inkeylen <= 0 ||
	    inmap == NULL || strlen(inmap) == 0)
		return (EINVAL);

	yprk.domain = context->domain;
	yprk.map = (char*)inmap;
	yprk.key.keydat_val = (char*)inkey;
	yprk.key.keydat_len = inkeylen;

	rv = clnt_call(context->client, YPPROC_MATCH,
		       (xdrproc_t)xdr_ypreq_key, &yprk,
		       (xdrproc_t)xdr_ypresp_val, &yprv, tv);
	if (rv != RPC_SUCCESS) {
		warnx("YPPROC_MATCH failed with %d", rv);
	} else {
		size_t tmp_len;
		char *tmp;

		tmp_len = yprv.val.valdat_len;
		tmp = calloc(1, tmp_len);
		if (tmp) {
			bcopy(yprv.val.valdat_val, tmp, tmp_len);
			tmp[tmp_len] = 0;
			*outvallen = tmp_len;
			*outval = tmp;
		}
		xdr_free((xdrproc_t)xdr_ypresp_val, &yprv);
		rv = 0;
	}
	return rv;
}

int
yp_first_r(void *ctx,
	   const char *inmap,
	   const char **outval, size_t *outvallen)
{
	yp_context_t *context = ctx;
        struct ypresp_val yprv = { 0 };
	struct timeval tv = { .tv_sec = 5, };
	struct ypreq_key yprk = { };
	int rv;
	
	if (ctx == NULL)
		return (EINVAL);

	if (inmap == NULL || strlen(inmap) == 0)
		return (EINVAL);

	yprk.domain = context->domain;
	yprk.map = (char*)inmap;

	rv = clnt_call(context->client, YPPROC_FIRST,
		       (xdrproc_t)xdr_ypreq_nokey, &yprk,
		       (xdrproc_t)xdr_ypresp_val, &yprv, tv);
	if (rv != RPC_SUCCESS) {
		warnx("YPPROC_FIRST failed with %d", rv);
	} else {
		size_t tmp_len;
		char *tmp;

		tmp_len = yprv.val.valdat_len;
		tmp = calloc(1, tmp_len);
		if (tmp) {
			bcopy(yprv.val.valdat_val, tmp, tmp_len);
			tmp[tmp_len] = 0;
			*outvallen = tmp_len;
			*outval = tmp;
		}
		xdr_free((xdrproc_t)xdr_ypresp_val, &yprv);
		rv = 0;
	}
	return rv;
}

int
yp_next_r(void *ctx,
	   const char *inmap,
	   const char *inkey, size_t inkeylen,
	   const char **outval, size_t *outvallen)
{
	yp_context_t *context = ctx;
        struct ypresp_val yprv = { 0 };
	struct timeval tv = { .tv_sec = 5, };
	struct ypreq_key yprk;
	int rv;
	
	if (ctx == NULL)
		return (EINVAL);

	if (inkey == NULL || strlen(inkey) == 0 || inkeylen <= 0 ||
	    inmap == NULL || strlen(inmap) == 0)
		return (EINVAL);

	yprk.domain = context->domain;
	yprk.map = (char*)inmap;
	yprk.key.keydat_val = (char*)inkey;
	yprk.key.keydat_len = inkeylen;

	rv = clnt_call(context->client, YPPROC_NEXT,
		       (xdrproc_t)xdr_ypreq_key, &yprk,
		       (xdrproc_t)xdr_ypresp_val, &yprv, tv);
	if (rv != RPC_SUCCESS) {
		warnx("YPPROC_MATCH failed with %d", rv);
	} else {
		size_t tmp_len;
		char *tmp;

		tmp_len = yprv.val.valdat_len;
		tmp = calloc(1, tmp_len);
		if (tmp) {
			bcopy(yprv.val.valdat_val, tmp, tmp_len);
			tmp[tmp_len] = 0;
			*outvallen = tmp_len;
			*outval = tmp;
		}
		xdr_free((xdrproc_t)xdr_ypresp_val, &yprv);
		rv = 0;
	}
	return rv;
}

#ifdef TEST
int
main(int ac, char **av)
{
	void *ctx;
	const char *domain = NULL;
	const char *server = NULL;
	const char *user = "testuser";

	if (ac > 1)
		domain = av[1];
	if (ac > 2)
		server = av[2];
	if (ac > 3)
		user = av[3];
	if (ac > 4)
		errx(1, "Usage: %s [domain [server [user]]]", av[0]);

	ctx = yp_init(domain, server);
	if (ctx == NULL)
		err(1, "Could not create YP context");
	else {
		const char *map = "passwd.byname";
		const char *out_val;
		size_t out_len;
		int x;

		x = yp_match_r(ctx, map, user, strlen(user), 
			       &out_val, &out_len);
		if (x == 0) {
			printf("got %s\n", out_val);
		} else {
			warnc(x, "Returned %d", x);
		}
	}
	return 0;
}
#endif /* TEST */
