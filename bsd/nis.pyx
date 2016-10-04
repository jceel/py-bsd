from __future__ import print_function
import os
import sys
import cython

from libc.stdlib cimport free
from libc.string cimport strerror
from libc.errno cimport *
cimport defs

cdef extern from "yp_client.h":
    cdef extern void *yp_client_init(const char *domain, const char *server)
    cdef extern void yp_client_close(void *context)
    cdef extern int yp_client_match(void *context,
                                    const char *inmap, const char *inkey, size_t inkeylen,
                                    char **outval, size_t *outvallen)
    cdef extern int yp_client_first(void *context, const char *inmap,
                                    const char **outkey, size_t *outkeylen,
                                    const char **outval, size_t *outvallen)
    cdef extern int yp_client_next(void *context, const char *inmap,
                                   const char *inkey, size_t inkeylen,
                                   const char **outkey, size_t *outkeylen,
                                   const char **outval, size_t *outvallen)
                                    
cdef extern from "pwd.h":
    ctypedef int time_t
    ctypedef int uid_t
    ctypedef int gid_t
    
    cdef struct passwd:
        char	*pw_name
        char	*pw_passwd
        uid_t	pw_uid
        gid_t	pw_gid
        time_t	pw_change
        char	*pw_class
        char	*pw_gecos
        char	*pw_dir
        char	*pw_shell
        time_t	pw_expire
        int	pw_fields
        
cdef _make_pwent(entry):
    cdef passwd retval
    fields = entry.split(':')
    retval.pw_name = fields[0]
    retval.pw_passwd = fields[1]
    retval.pw_uid = int(fields[2])
    retval.pw_gid = int(fields[3])
    retval.pw_gecos = fields[4]
    retval.pw_dir = fields[5]
    retval.pw_shell = fields[6]
    # Now all the ones not defined by that
    retval.pw_change = 0
    retval.pw_class = ""
    retval.pw_expire = 0
    retval.pw_fields = 1
    return retval

cdef class NIS(object):
    cdef void *ctx
    cdef const char *domain
    cdef const char *server
    def __init__(self, domain=None, server=None):
        self.ctx = yp_client_init(domain, server)
        if self.ctx == NULL:
            raise OSError(ENOMEM, strerror(ENOMEM))
        self.domain = domain
        self.server = server
        return

    def _getpw(self, mapname, keyvalue):
        cdef char *pw_ent = NULL
        cdef size_t pw_ent_len
        
        rv = yp_client_match(self.ctx, mapname, keyvalue, len(keyvalue), &pw_ent, &pw_ent_len)
        if rv != 0:
            raise OSError(rv, strerror(rv))
        
        retval = _make_pwent(pw_ent.decode('utf-8'))
        free(pw_ent)
        if retval:
            return retval
        raise OSError(ENOENT, "Cannot find key {} in map {}".format(keyvalue, mapname))
        
    def getpwent(self):
        """
        This is slightly different from the libc routine.
        We simply call yp_client_first() for the proper map, and then
        yield results until yp_client_next() returns an error.
        """
        cdef const char *first_key = NULL
        cdef const char *next_key = NULL
        cdef const char *out_value = NULL
        cdef size_t first_keylen, next_keylen, out_len
        
        if os.geteuid() == 0:
            mapname = "master.passwd.byname"
        else:
            mapname = "passwd.byname"

        try:
            rv = yp_client_first(self.ctx, mapname,
                                 &next_key, &next_keylen,
                                 &out_value, &out_len)
            while rv == 0:
                retval = _make_pwent(out_value.decode('utf-8'))
                free(<void*>out_value)
                free(<void*>first_key)
                first_key = next_key
                first_keylen = next_keylen
                next_key = NULL
                next_keylen = 0
                yield retval
                rv = yp_client_next(self.ctx, mapname,
                                    first_key, first_keylen,
                                    &next_key, &next_keylen,
                                    &out_value, &out_len)
        finally:
            if first_key:
                free(<void*>first_key)
            if next_key:
                free(<void*>next_key)
    
            
    def getpwnam(self, name):
        if os.geteuid() == 0:
            mapname = "master.passwd.byname"
        else:
            mapname = "passwd.byname"
            
        return self._getpw(mapname, name)

    def getpwuid(self, uid):
        if os.geteuid() == 0:
            mapname = "master.passwd.byuid"
        else:
            mapname = "passwd.byuid"
            
        return self._getpw(mapname, str(uid))
    
    
