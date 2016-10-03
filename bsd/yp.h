#ifndef _YP_H
# define _YP_H

/*
 * Return a context object to connect to the given
 * server for the given domain.
 * If domain is NULL, it will use getdomainname();
 * if that fails, it returns NULL and sets errno.
 * (If no domainname is set, it sets errno to ENOENT.)
 * If server is NULL, then it will query ypbind on
 * localhost; if that fails, it returns NULL and sets
 * errno.
 * If it cannot connect to the server for the domain,
 * 
 */
void *yp_init(const char *domain, const char *server);
void yp_close(void *context);

int yp_match_r(void *context,
	       const char *inmap,
	       const char *inkey,
	       size_t inkeylen,
	       char **outval,
	       size_t *outvallen);

#endif /* _YP_H */
