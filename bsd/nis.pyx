from __future__ import print_function
import os
import sys
import cython

from libc.stdlib cimport free
from libc.string cimport strerror
from libc.errno cimport *
cimport defs

cdef extern from "yp.h":
    cdef extern void *yp_init(const char *domain, const char *server)
    cdef extern void yp_close(void *context)
    cdef extern int yp_match_r(void *context,
                               const char *inmap, const char *inkey, size_t inkeylen,
                               char **outval, size_t *outvallen)
    
ctypedef struct pwd:
    char *pw_name
    char *pw_passwd
    int   pw_uid
    int   pw_gid
    char *pw_gecos
    char *pw_dir
    char *pw_shell
    
cdef class NIS(object):
    cdef void *ctx
    cdef const char *domain
    cdef const char *server
    def __init__(self, domain=None, server=None):
        self.ctx = yp_init(domain, server)
        if self.ctx == NULL:
            raise OSError(ENOMEM, strerror(ENOMEM))
        self.domain = domain
        self.server = server
        return

    def _getpw(self, mapname, keyvalue):
        cdef char *pw_ent = NULL
        cdef size_t pw_ent_len
        cdef pwd retval
        
        rv = yp_match_r(self.ctx, mapname, keyvalue, len(keyvalue), &pw_ent, &pw_ent_len)
        if rv != 0:
            raise OSError(rv, strerror(rv))
        
        fields = pw_ent.decode('utf-8').split(":")
	free(pw_ent)
        if fields:
            retval.pw_name = fields[0]
            retval.pw_passwd = fields[1]
            retval.pw_uid = int(fields[2])
            retval.pw_gid = int(fields[3])
            retval.pw_gecos = fields[4]
            retval.pw_dir = fields[5]
            retval.pw_shell = fields[6]
            return retval
        raise OSError(ENOENT, "Cannot find key {} in map {}".format(keyvalue, mapname))
        
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
    
    
