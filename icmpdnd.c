/*
 *  icmpdnd - ICMP Domain Name responder daemon for Linux
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
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/poll.h>
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
    int i, n, ret;
    int c, cs, s4, s6, namelen, datalen;
    int daemonize, ttl;
    unsigned char buf[65536];
    struct sockaddr_storage name;
    struct reqhdr req;
    struct rephdr rep;
    struct iphdr iphdr;
    size_t hdrlen;
    struct pollfd pfd[2];
    time_t curtime, lasterr;
    
    daemonize = 1;
    ttl = 3600;
    while((c = getopt(argc, argv, "nht:")) != -1) {
	switch(c) {
	case 't':
	    ttl = atoi(optarg);
	    break;
	case 'n':
	    daemonize = 0;
	    break;
	case 'h':
	case '?':
	case ':':
	default:
	    fprintf(stderr, "usage: icmpdnd [-n]");
	    exit((c == 'h')?0:1);
	}
    }
    
    s4 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    s6 = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMP);
    if((s4 < 0) && (s6 < 0)) {
	perror("could not open raw socket");
	exit(1);
    }
    
    if(daemonize)
	daemon(0, 0);
    
    openlog("icmpdnd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    
    alive = 1;
    lasterr = 0;
    while(alive) {
	n = 0;
	if(s4 >= 0) {
	    pfd[n].fd = s4;
	    pfd[n].events = POLLIN;
	    n++;
	}
	if(s6 >= 0) {
	    pfd[n].fd = s6;
	    pfd[n].events = POLLIN;
	    n++;
	}
	ret = poll(pfd, n, -1);

	curtime = time(NULL);
	if(ret < 0) {
	    if(errno == EINTR)
		continue;
	    syslog(LOG_ERR, "error while polling sockets: %m");
	    if(lasterr == curtime) {
		syslog(LOG_CRIT, "exiting due to repeated errors");
		exit(1);
	    }
	    lasterr = curtime;
	}
	
	for(i = 0; i < n; i++) {
	    if((pfd[i].revents & POLLIN) == 0)
		continue;
	    cs = pfd[i].fd;
	    namelen = sizeof(name);
	    memset(&name, 0, sizeof(name));
	    ret = recvfrom(cs, buf, sizeof(buf), 0, (struct sockaddr *)&name, &namelen);
	    if(ret < 0) {
		syslog(LOG_WARNING, "error while receiving datagram: %m");
		continue;
	    }
	    
	    if(cs == s4) {
		if(ret < sizeof(iphdr) + sizeof(req))
		    continue;
		hdrlen = sizeof(iphdr);
		memcpy(&iphdr, buf, sizeof(iphdr));
		if(iphdr.protocol != IPPROTO_ICMP)
		    continue;
	    } else if(cs == s6) {
		if(ret < sizeof(req))
		    continue;
		((struct sockaddr_in6 *)&name)->sin6_port = 0;
		hdrlen = 0;
	    } else {
		syslog(LOG_CRIT, "strangeness!");
		abort();
	    }
	    memcpy(&req, buf + hdrlen, sizeof(req));
	    if(req.type != ICMP_NAMEREQ)
		continue;
	    rep.type = ICMP_NAMEREP;
	    rep.code = 0;
	    rep.id = req.id;
	    rep.seq = req.seq;
	    rep.ttl = htonl(ttl);
	    memcpy(buf, &rep, sizeof(rep));
	    datalen = filldn(buf + sizeof(rep));
	
	    cksum(buf, datalen + sizeof(rep));
	
	    /* XXX: The correct source address needs to be filled in from
	     * the request's destination address. */
	    ret = sendto(cs, buf, datalen + sizeof(rep), 0, (struct sockaddr *)&name, namelen);
	    if(ret < 0)
		syslog(LOG_WARNING, "error in sending reply: %m");
	}
    }
    
    close(s4);
    close(s6);
    return(0);
}
