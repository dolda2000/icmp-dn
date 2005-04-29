#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <nss.h>
#include <sys/types.h>
#include <fcntl.h>

enum nss_status _nss_icmp_gethostbyaddr_r(const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    int ret;
    struct retstruct {
	char *aliaslist[16];
	char *addrlist[2];
	char retaddr[16];
    } *retbuf;
    char addrbuf[1024];
    int an, thislen;
    char *p, *p2, *p3;
    u_int8_t *ap;
    pid_t child;
    int pfd[2];
    int rl;
    
    retbuf = (struct retstruct *)buffer;
    if((buflen < sizeof(*retbuf)) || (len > sizeof(retbuf->retaddr))) {
	*errnop = ENOMEM;
	*h_errnop = NETDB_INTERNAL;
	return(NSS_STATUS_UNAVAIL);
    }
    
    ap = (u_int8_t *)addr;
    if(inet_ntop(af, addr, addrbuf, sizeof(addrbuf)) == NULL) {
	*errnop = errno;
	*h_errnop = NETDB_INTERNAL;
	return(NSS_STATUS_UNAVAIL);
    }
    
    if(pipe(pfd)) {
	*errnop = errno;
	*h_errnop = NETDB_INTERNAL;
	return(NSS_STATUS_UNAVAIL);
    }
    /* I honestly don't know if it is considered OK to fork in other
     * people's programs. We need a SUID worker, though, so there's
     * little choice that I can see. */
    if((child = fork()) < 0) {
	*errnop = errno;
	*h_errnop = NETDB_INTERNAL;
	return(NSS_STATUS_UNAVAIL);
    }
    
    if(child == 0) {
	int i, fd;
	
	if((fd = open("/dev/null", O_WRONLY)) < 0)
	    exit(127);
	close(pfd[0]);
	dup2(pfd[1], 1);
	dup2(fd, 2);
	for(i = 3; i < FD_SETSIZE; i++)
	    close(i);
	
	execlp("idnlookup", "idnlookup", addrbuf, NULL);
	exit(127);
    }
    
    close(pfd[1]);
    
    rl = 0;
    do {
	ret = read(pfd[0], addrbuf + rl, sizeof(addrbuf) - rl);
	if(ret < 0) {
	    *errnop = errno;
	    *h_errnop = NETDB_INTERNAL;
	    close(pfd[0]);
	    return(NSS_STATUS_UNAVAIL);
	}
	rl += ret;
	if(rl >= sizeof(addrbuf) - 1) {
	    *errnop = ENOMEM;
	    *h_errnop = NETDB_INTERNAL;
	    close(pfd[0]);
	    return(NSS_STATUS_UNAVAIL);
	}
    } while(ret != 0);
    addrbuf[rl] = 0;
    close(pfd[0]);
    
    an = 0;
    p = addrbuf;
    p3 = buffer + sizeof(*retbuf);
    while((p2 = strchr(p, '\n')) != NULL) {
	*p2 = 0;
	thislen = p2 - p;
	if(thislen == 0)
	    continue;
	if((p3 - buffer) + thislen + 1 > buflen) {
	    *errnop = ENOMEM;
	    *h_errnop = NETDB_INTERNAL;
	    return(NSS_STATUS_UNAVAIL);
	}
	memcpy(p3, p, thislen + 1);
	retbuf->aliaslist[an] = p3;
	p3 += thislen + 1;
	p = p2 + 1;
	if(++an == 16) {
	    *errnop = ENOMEM;
	    *h_errnop = NETDB_INTERNAL;
	    return(NSS_STATUS_UNAVAIL);
	}
    }
    if(an == 0) {
	*h_errnop = TRY_AGAIN; /* XXX: Is this correct? */
	return(NSS_STATUS_NOTFOUND);
    }
    retbuf->aliaslist[an] = NULL;
    
    memcpy(retbuf->retaddr, addr, len);
    retbuf->addrlist[0] = retbuf->retaddr;
    retbuf->addrlist[1] = NULL;
    result->h_name = retbuf->aliaslist[0];
    result->h_aliases = retbuf->aliaslist;
    result->h_addr_list = retbuf->addrlist;
    result->h_addrtype = af;
    result->h_length = len;
    
    *h_errnop = NETDB_SUCCESS;
    return(NSS_STATUS_SUCCESS);
}
