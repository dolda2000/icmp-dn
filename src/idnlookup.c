/*
 *  idnlookup - ICMP Domain Name lookup utility for Linux
 *  Should be installed SUID root, even though I don't know if it's secure yet. :-)
 *  Copyright (C) 2005 Fredrik Tolf <fredrik@dolda2000.com>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/time.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

struct icmphdr {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
};

struct reqhdr {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t seq;
};

struct rephdr {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t seq;
    int32_t ttl;
    
};

#define ICMP_NAMEREQ 37
#define ICMP_NAMEREP 38

unsigned char buf[65536];

/* DN decompression not yet implemented, since I don't know where to
 * begin counting the offset from -- the beginning of the ICMP
 * payload, or from the beginning of the DN data buffer? */
void printdn(FILE *f, unsigned char *dnbuf, size_t size, int onlyfirst)
{
    unsigned char *p;
    
    p = dnbuf;
    while(p - dnbuf < size) {
	while(*p != 0) {
	    if(*p & 0xc0) {
		fprintf(stderr, "domain name decompression not implemented, aborting\n");
		exit(1);
	    }
	    fprintf(f, "%.*s", (int)*p, p + 1);
	    p += 1 + (int)*p;
	    if(*p != 0)
		fprintf(f, ".");
	}
	p++;
	fprintf(f, "\n");
	if(onlyfirst)
	    break;
    }
}

void cksum(void *hdr, size_t len)
{
    struct icmphdr *ih;
    u_int8_t *cb;
    int i;
    int b1, b2;
    
    ih = (struct icmphdr *)hdr;
    cb = (u_int8_t *)hdr;
    ih->checksum = 0;
    b1 = b2 = 0;
    for(i = 0; i < (len & ~1); i += 2) {
	b1 += cb[i];
	b2 += cb[i + 1];
    }
    if(i & 1)
	b1 += cb[len - 1];
    while(1) {
	if(b1 >= 256) {
	    b2 += b1 >> 8;
	    b1 &= 0xff;
	    continue;
	}
	if(b2 >= 256) {
	    b1 += b2 >> 8;
	    b2 &= 0xff;
	    continue;
	}
	break;
    }
    cb = (u_int8_t *)&ih->checksum;
    cb[0] = ~(u_int8_t)b1;
    cb[1] = ~(u_int8_t)b2;
}

void usage(void)
{
    fprintf(stderr, "usage: idnlookup [-hTa] [-t timeout] host\n");
}

int main(int argc, char **argv)
{
    int ret;
    int s, c;
    int id;
    int namelen;
    struct reqhdr req;
    struct rephdr rep;
    struct iphdr iphdr;
    size_t hdrlen;
    struct addrinfo *ai, *cai, aihint;
    struct pollfd pfd;
    struct timeval tvb, tvc;
    struct sockaddr_storage name;
    int timeout, dispttl, onlyfirst;
    int elapsed, timedout, found;
    
    timeout = 3000;
    dispttl = 0;
    onlyfirst = 1;
    while((c = getopt(argc, argv, "haTt:")) != -1) {
	switch(c) {
	case 't':
	    timeout = atoi(optarg);
	    break;
	case 'a':
	    onlyfirst = 0;
	    break;
	case 'T':
	    dispttl = 1;
	    break;
	case 'h':
	case '?':
	case ':':
	default:
	    usage();
	    exit((c == 'h')?0:1);
	}
    }
    
    if(argc - optind < 1) {
	usage();
	exit(1);
    }
    
    memset(&aihint, 0, sizeof(aihint));
    aihint.ai_socktype = SOCK_RAW;
    aihint.ai_protocol = IPPROTO_ICMP;
    ret = getaddrinfo(argv[optind], NULL, &aihint, &ai);
    
    for(cai = ai; cai != NULL; cai = cai->ai_next) {
	if((s = socket(cai->ai_family, SOCK_RAW, IPPROTO_ICMP)) < 0) {
	    perror("could not create raw socket");
	    exit(1);
	}
	
	id = random() % 65536;
	memset(&req, 0, sizeof(req));
	req.type = ICMP_NAMEREQ;
	req.id = htons(id);
	cksum(&req, sizeof(req));
	
	ret = sendto(s, &req, sizeof(req), 0, cai->ai_addr, cai->ai_addrlen);
	if(ret < 0) {
	    perror("sendto");
	    exit(1);
	} else if(ret != sizeof(req)) {
	    fprintf(stderr, "socket would not send entire packet\n");
	    exit(1);
	}
	
	timedout = 0;
	found = 0;
	gettimeofday(&tvb, NULL);
	while(1) {
	    pfd.fd = s;
	    pfd.events = POLLIN;
	    gettimeofday(&tvc, NULL);
	    elapsed = ((tvc.tv_sec - tvb.tv_sec) * 1000) + ((tvc.tv_usec - tvb.tv_usec) / 1000);
	    if(elapsed >= timeout) {
		timedout = 1;
		break;
	    }
	    ret = poll(&pfd, 1, timeout - elapsed);
	    if(ret < 0) {
		perror("idnlookup: reading data");
		exit(1);
	    }
	    
	    if(pfd.revents & POLLIN) {
		namelen = sizeof(name);
		ret = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&name, &namelen);
		if(ret < 0) {
		    perror("idnlookup: receiving data");
		    exit(1);
		}
		
		if(name.ss_family != cai->ai_addr->sa_family)
		    continue;
		if(name.ss_family == AF_INET) {
		    if(memcmp(&(((struct sockaddr_in *)&name)->sin_addr), &(((struct sockaddr_in *)cai->ai_addr)->sin_addr), sizeof(struct in_addr)))
			continue;
		    if(ret < sizeof(iphdr) + sizeof(rep))
			continue;
		    hdrlen = sizeof(iphdr);
		    memcpy(&iphdr, buf, sizeof(iphdr));
		    if(iphdr.protocol != IPPROTO_ICMP)
			continue;
		} else if(name.ss_family == AF_INET6) {
		    if(memcmp(&(((struct sockaddr_in6 *)&name)->sin6_addr), &(((struct sockaddr_in6 *)cai->ai_addr)->sin6_addr), sizeof(struct in6_addr)))
			continue;
		    if(ret < sizeof(rep))
			continue;
		    hdrlen = 0;
		} else {
		    continue;
		}
		
		memcpy(&rep, buf + hdrlen, sizeof(rep));
		if(rep.type != ICMP_NAMEREP)
		    continue;
		if((ntohs(rep.id) != id) || (ntohs(rep.seq != 0)))
		    continue;
		
		found = 1;
		break;
	    }
	}
	
	close(s);
	
	if(found) {
	    if(dispttl)
		printf("%i\n", ntohl(rep.ttl));
	    printdn(stdout, buf + hdrlen + sizeof(rep), ret - hdrlen - sizeof(rep), onlyfirst);
	    break;
	}
    }
    
    if(timedout) {
	fprintf(stderr, "idnlookup: timeout\n");
	exit(1);
    }
    
    return(0);
}

/*
 * Local Variables:
 * compile-command: "make CFLAGS='-Wall -g'"
 * End:
 */
