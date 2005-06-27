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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef MAXHNAME
#define MAXHNAME 1024
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

volatile int alive;
char myname[MAXHNAME] = "";

void setname(char *newname)
{
    int nl;
    
    if(newname == NULL) {
	if(gethostname(myname, sizeof(myname)) < 0) {
	    perror("gethostname");
	    exit(1);
	}
	nl = strlen(myname);
	myname[nl++] = '.';
	if(getdomainname(myname + nl, sizeof(myname) - nl) < 0) {
	    perror("getdomainname");
	    exit(1);
	}
	if(strlen(myname + nl) != 0) {
	    nl = strlen(myname);
	    myname[nl++] = '.';
	}
	myname[nl] = 0;
    } else {
	strcpy(myname, newname);
	nl = strlen(myname);
	if(myname[nl - 1] != '.') {
	    myname[nl] = '.';
	    myname[nl + 1] = 0;
	}
    }
}

size_t filldn(char *dst)
{
    char *p, *p2, *dp;
    char namebuf[MAXHNAME];
    
    strcpy(namebuf, myname);
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
    int c, cs, s4, s6, datalen;
    int daemonize, ttl;
    unsigned char buf[65536];
    struct sockaddr_storage name;
    struct reqhdr req;
    struct rephdr rep;
    struct iphdr iphdr;
    struct msghdr mhdr;
    struct iovec iov;
    char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    size_t hdrlen;
    struct pollfd pfd[2];
    time_t curtime, lasterr;
    
    daemonize = 1;
    ttl = 3600;
    while((c = getopt(argc, argv, "nht:d:")) != -1) {
	switch(c) {
	case 't':
	    ttl = atoi(optarg);
	    break;
	case 'd':
	    setname(optarg);
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
    if(*myname == 0)
	setname(NULL);
    
    s4 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    s6 = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMP);
    if((s4 < 0) && (s6 < 0)) {
	perror("could not open raw socket");
	exit(1);
    }
    if(s6 >= 0) {
	i = 1;
	if(setsockopt(s6, IPPROTO_IPV6, IPV6_PKTINFO, &i, sizeof(i))) {
	    perror("could not set IPV6_PKTINFO sockopt");
	    exit(1);
	}
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
	    memset(&name, 0, sizeof(name));
	    
	    iov.iov_len = sizeof(buf);
	    iov.iov_base = buf;
	    mhdr.msg_name = &name;
	    mhdr.msg_namelen = sizeof(name);
	    mhdr.msg_iov = &iov;
	    mhdr.msg_iovlen = 1;
	    mhdr.msg_control = cmsgbuf;
	    mhdr.msg_controllen = sizeof(cmsgbuf);
	    
	    ret = recvmsg(cs, &mhdr, 0);
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
		mhdr.msg_control = NULL;
		mhdr.msg_controllen = 0;
	    } else if(cs == s6) {
		if(ret < sizeof(req))
		    continue;
		((struct sockaddr_in6 *)&name)->sin6_port = 0;
		hdrlen = 0;
		/* Just keep mhdr.msg_control. */
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
	    
	    iov.iov_len = sizeof(rep) + datalen;
	    iov.iov_base = buf;
	    mhdr.msg_iov = &iov;
	    mhdr.msg_iovlen = 1;
	    ret = sendmsg(cs, &mhdr, 0);
	    if(ret < 0)
		syslog(LOG_WARNING, "error in sending reply: %m");
	}
    }
    
    close(s4);
    close(s6);
    return(0);
}

/*
 * Local Variables:
 * compile-command: "make CFLAGS='-Wall -g'"
 * End:
 */
