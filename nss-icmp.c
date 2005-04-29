#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <nss.h>
#include <sys/types.h>
#include <fcntl.h>

#define CONFIGFILE "/etc/nss-icmp.conf"

struct cache {
    struct cache *next, *prev;
    char *addr;
    socklen_t addrlen;
    int af;
    int notfound;
    char **names;
    time_t at, ttl;
};

static int inited = 0;
static int timeout = -1;
static int usecache = 1;
static time_t nfttl = 300;
static struct cache *cache = NULL;

static void readconfig(void)
{
    FILE *f;
    char linebuf[1024];
    char *p, *p2;
    
    if((f = fopen(CONFIGFILE, "r")) == NULL)
	return;
    
    while(fgets(linebuf, sizeof(linebuf), f) != NULL) {
	if(linebuf[0] == '#')
	    continue;
	if((p = strchr(linebuf, '\n')) != NULL)
	    *p = 0;
	if((p = strchr(linebuf, ' ')) != NULL) {
	    p2 = p + 1;
	    *p = 0;
	}
	if(!strcmp(linebuf, "timeout")) {
	    if(p2 == NULL)
		continue;
	    timeout = atoi(p2);
	}
	if(!strcmp(linebuf, "ttlnotfound")) {
	    if(p2 == NULL)
		continue;
	    nfttl = atoi(p2);
	}
	if(!strcmp(linebuf, "nocache")) {
	    usecache = 0;
	}
    }
    
    fclose(f);
}

static void freecache(struct cache *cc)
{
    int i;
    
    if(cc->next != NULL)
	cc->next->prev = cc->prev;
    if(cc->prev != NULL)
	cc->prev->next = cc->next;
    if(cc == cache)
	cache = cc->next;
    if(cc->addr != NULL)
	free(cc->addr);
    if(cc->names != NULL) {
	for(i = 0; cc->names[i] != NULL; i++)
	    free(cc->names[i]);
	free(cc->names);
    }
    free(cc);
}

static void cachenotfound(const void *addr, socklen_t len, int af, time_t ttl)
{
    struct cache *cc;
    
    for(cc = cache; cc != NULL; cc = cc->next) {
	if((cc->af == af) && (cc->addrlen == len) && !memcmp(cc->addr, addr, len))
	    break;
    }
    if(cc == NULL) {
	if((cc = malloc(sizeof(*cc))) == NULL)
	    return;
	memset(cc, 0, sizeof(*cc));
	if((cc->addr = malloc(len)) == NULL) {
	    freecache(cc);
	    return;
	}
	memcpy(cc->addr, addr, len);
	cc->addrlen = len;
	cc->af = af;
	cc->at = time(NULL);
	cc->ttl = ttl;
	
	cc->notfound = 1;
	
	cc->next = cache;
	if(cache != NULL)
	    cache->prev = cc;
	cache = cc;
    }
}

static void updatecache(const void *addr, socklen_t len, int af, char **names, time_t ttl)
{
    int i;
    struct cache *cc;
    
    for(cc = cache; cc != NULL; cc = cc->next) {
	if((cc->af == af) && (cc->addrlen == len) && !memcmp(cc->addr, addr, len))
	    break;
    }
    if(cc == NULL) {
	if((cc = malloc(sizeof(*cc))) == NULL)
	    return;
	memset(cc, 0, sizeof(*cc));
	if((cc->addr = malloc(len)) == NULL) {
	    freecache(cc);
	    return;
	}
	memcpy(cc->addr, addr, len);
	cc->addrlen = len;
	cc->af = af;
	cc->at = time(NULL);
	cc->ttl = ttl;
	
	for(i = 0; names[i] != NULL; i++);
	if((cc->names = malloc(sizeof(*(cc->names)) * (i + 1))) == NULL) {
	    freecache(cc);
	    return;
	}
	memset(cc->names, 0, sizeof(*(cc->names)) * (i + 1));
	for(i = 0; names[i] != NULL; i++) {
	    if((cc->names[i] = malloc(strlen(names[i]) + 1)) == NULL) {
		freecache(cc);
		return;
	    }
	    strcpy(cc->names[i], names[i]);
	}
	
	cc->next = cache;
	if(cache != NULL)
	    cache->prev = cc;
	cache = cc;
    }
}

static void expirecache(void)
{
    struct cache *cc, *next;
    time_t now;
    
    now = time(NULL);
    for(cc = cache; cc != NULL; cc = next) {
	next = cc->next;
	if(now - cc->at > cc->ttl) {
	    freecache(cc);
	    continue;
	}
    }
}

enum nss_status _nss_icmp_gethostbyaddr_r(const void *addr, socklen_t len, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
    int i, ret;
    struct retstruct {
	char *aliaslist[16];
	char *addrlist[2];
	char retaddr[16];
    } *retbuf;
    char addrbuf[1024];
    int an, thislen, ttl;
    char *p, *p2, *p3;
    u_int8_t *ap;
    pid_t child;
    int pfd[2];
    int rl;
    struct cache *cc;
    
    if(!inited) {
	readconfig();
	inited = 1;
    }
    
    retbuf = (struct retstruct *)buffer;
    if((buflen < sizeof(*retbuf)) || (len > sizeof(retbuf->retaddr))) {
	*errnop = ENOMEM;
	*h_errnop = NETDB_INTERNAL;
	return(NSS_STATUS_UNAVAIL);
    }
    
    if(usecache) {
	expirecache();
	for(cc = cache; cc != NULL; cc = cc->next) {
	    if((cc->af == af) && (cc->addrlen == len) && !memcmp(cc->addr, addr, len))
		break;
	}
    } else {
	cc = NULL;
    }
    
    if(cc == NULL) {
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
	    char timeoutbuf[128];
	
	    if((fd = open("/dev/null", O_WRONLY)) < 0)
		exit(127);
	    close(pfd[0]);
	    dup2(pfd[1], 1);
	    dup2(fd, 2);
	    for(i = 3; i < FD_SETSIZE; i++)
		close(i);
	
	    if(timeout != -1) {
		snprintf(timeoutbuf, sizeof(timeoutbuf), "%i", timeout);
		execlp("idnlookup", "idnlookup", "-Tt", timeoutbuf, addrbuf, NULL);
	    } else {
		execlp("idnlookup", "idnlookup", "-T", addrbuf, NULL);
	    }
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
	
	if((p = strchr(addrbuf, '\n')) == NULL) {
	    if(usecache)
		cachenotfound(addr, len, af, nfttl);
	    *h_errnop = TRY_AGAIN; /* XXX: Is this correct? */
	    return(NSS_STATUS_NOTFOUND);
	}
	*(p++) = 0;
	ttl = atoi(addrbuf);
	
	an = 0;
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
	    if(usecache)
		cachenotfound(addr, len, af, nfttl);
	    *h_errnop = TRY_AGAIN; /* XXX: Is this correct? */
	    return(NSS_STATUS_NOTFOUND);
	}
	retbuf->aliaslist[an] = NULL;
	
	if(usecache)
	    updatecache(addr, len, af, retbuf->aliaslist, ttl);
    } else {
	if(cc->notfound) {
	    *h_errnop = TRY_AGAIN; /* XXX: Is this correct? */
	    return(NSS_STATUS_NOTFOUND);
	}
	
	p3 = buffer + sizeof(*retbuf);
	for(i = 0; cc->names[i] != NULL; i++) {
	    thislen = strlen(cc->names[i]);
	    if((p3 - buffer) + thislen + 1 > buflen) {
		*errnop = ENOMEM;
		*h_errnop = NETDB_INTERNAL;
		return(NSS_STATUS_UNAVAIL);
	    }
	    memcpy(p3, cc->names[i], thislen + 1);
	    retbuf->aliaslist[an] = p3;
	    p3 += thislen + 1;
	    if(++an == 16) {
		*errnop = ENOMEM;
		*h_errnop = NETDB_INTERNAL;
		return(NSS_STATUS_UNAVAIL);
	    }
	}
    }
    
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
