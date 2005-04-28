/*
 *  icmpdnd - ICMP Domain Name responder daemon for Linux
 *  Copyright (C) 2004 Fredrik Tolf <fredrik@dolda2000.com>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/types.h>

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

#define TTL 3600

volatile int alive;

size_t filldn(char *dst)
{
    char *p, *p2, *dp;
    char namebuf[1024];
    int hl;
    
    if(gethostname(namebuf, sizeof(namebuf)) < 0) {
	perror("gethostname");
	exit(1);
    }
    hl = strlen(namebuf);
    namebuf[hl++] = '.';
    if(getdomainname(namebuf + hl, sizeof(namebuf) - hl) < 0) {
	perror("getdomainname");
	exit(1);
    }
    if(strlen(namebuf + hl) != 0) {
	hl = strlen(namebuf);
	namebuf[hl++] = '.';
    }
    namebuf[hl] = 0;
    
    p = namebuf;
    dp = dst;
    while((p2 = strchr(p, '.')) != NULL) {
	*p2 = 0;
	*(dp++) = p2 - p;
	memcpy(dp, p, p2 - p);
	dp += p2 - p;
	p = p2 + 1;
    }
    *(dp++) = 0;
    
    return(dp - dst);
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

int main(int argc, char **argv)
{
    int ret;
    int s, namelen, datalen;
    unsigned char buf[65536];
    struct sockaddr_in name;
    struct reqhdr req;
    struct rephdr rep;
    struct iphdr iphdr;

    if((s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
	perror("could not create raw socket");
	exit(1);
    }
    
    alive = 1;
    while(alive) {
	namelen = sizeof(name);
	ret = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&name, &namelen);
	if(ret < 0) {
	    if(errno == EINTR)
		continue;
	    perror("recvfrom");
	    exit(1);
	}
	if(ret < sizeof(iphdr))
	    continue;
	memcpy(&iphdr, buf, sizeof(iphdr));
	if(iphdr.protocol != IPPROTO_ICMP)
	    continue;
	if(ret < sizeof(iphdr) + sizeof(req))
	    continue;
	memcpy(&req, buf + sizeof(iphdr), sizeof(req));
	if(req.type != ICMP_NAMEREQ)
	    continue;
	rep.type = ICMP_NAMEREP;
	rep.code = 0;
	rep.id = req.id;
	rep.seq = req.seq;
	rep.ttl = htonl(TTL);
	memcpy(buf, &rep, sizeof(rep));
	datalen = filldn(buf + sizeof(rep));

	cksum(buf, datalen + sizeof(rep));

	ret = sendto(s, buf, datalen + sizeof(rep), 0, (struct sockaddr *)&name, namelen);
	if(ret < 0) {
	    perror("sendto");
	    exit(1);
	}
    }
    
    close(s);
    return(0);
}
