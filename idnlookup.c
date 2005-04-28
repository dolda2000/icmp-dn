#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

struct icmphdr {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t seq;
};

#define ICMP_NAMEREQ 37
#define ICMP_NAMEREP 38

int main(int argc, char **argv)
{
    int ret;
    int s;
    struct sockaddr_in host;
    struct icmphdr data;
    
    if((s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
	perror("could not create raw socket");
	exit(1);
    }
    
    host.sin_family = AF_INET;
    inet_aton("192.168.1.254", &host.sin_addr);
    
    memset(&data, 0, sizeof(data));
    data.type = ICMP_NAMEREQ;
    
    ret = sendto(s, &data, sizeof(data), 0, (struct sockaddr *)&host, sizeof(host));
    if(ret < 0) {
	perror("sendto");
    } else {
	printf("%i\n", ret);
    }
    close(s);
    return(0);
}
