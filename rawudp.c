#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// The packet length
#define PCKT_LEN 8192

unsigned short csum2(uint16_t *buf1, int nwords1, uint16_t *buf2, int nwords2) {
        unsigned long sum = 0;
        while (nwords1--)
                sum += *buf1++;
        if (buf2)
                while (nwords2--)
                        sum += *buf2++;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (unsigned short) (~sum);
}

unsigned short csum(uint16_t *buf, int nwords) {
        return csum2(buf, nwords, NULL, 0);
}

int usage(char **argv) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dest_ip> <dest_port>\n", *argv);
        exit(EX_USAGE);
}

struct udpph {
        in_addr_t udpph_src, udpph_dst;
        uint8_t udpph_zero, udpph_proto;
        uint16_t udpph_len;
};

#define RANDOM_FILE "/dev/urandom"

void get_random(void *buf, size_t bytes) {
        static int rfd = -1;
        if (rfd == -1)
                rfd = open(RANDOM_FILE, O_RDONLY);
        if (rfd == -1) {
                perror("open");
                exit(EX_OSERR);
        }
        while (bytes) {
                size_t br = read(rfd, buf, bytes);
                if (br > 0) {
                        buf += br;
                        bytes -= br;
                }
        }
}

// Source IP, source port, target IP, target port from the command line arguments
int main(int argc, char **argv) {
        if (argc != 5)
                usage(argv);

        in_addr_t s_ip = inet_addr(argv[1]);
        uint16_t s_port = htons(strtol(argv[2], 0, 0));
        in_addr_t d_ip = inet_addr(argv[3]);
        uint16_t d_port = htons(strtol(argv[4], 0, 0));

        // Set up the packet buffer and pointers within
        unsigned char buffer[PCKT_LEN];
        memset(buffer, 0, sizeof(buffer));
        struct ip *iph = (struct ip *) buffer;
        struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr));
        unsigned char *data = (unsigned char *) udph + sizeof(struct udphdr);

        int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sd < 0) {
                perror("socket");
                exit(EX_OSERR);
        }

        struct sockaddr_in s_in;
        memset(&s_in, 0, sizeof(struct sockaddr_in));
        s_in.sin_family = AF_INET;
        s_in.sin_port = s_port;
        s_in.sin_addr.s_addr = s_ip;

        struct sockaddr_in d_in;
        memset(&d_in, 0, sizeof(struct sockaddr_in));
        d_in.sin_family = AF_INET;
        d_in.sin_port = d_port;
        d_in.sin_addr.s_addr = d_ip;

        // Fabricate the IP header.
        iph->ip_hl = 5;  // Header length, in 32-bit words.
        iph->ip_v = IPVERSION;
        iph->ip_tos = IPTOS_LOWDELAY;
        iph->ip_off = 0;
        iph->ip_ttl = 64;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_src.s_addr = s_ip;
        iph->ip_dst.s_addr = d_ip;
        udph->source = s_port;
        udph->dest = d_port;

        int one = 1;
        // Inform the kernel do not fill up the packet structure. we will build our own...
        if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
                perror("setsockopt");
                exit(EX_OSERR);
        }

        // Send loop, send for every 2 second for 100 count
        while (1) {
                uint16_t data_len;
                get_random(&data_len, sizeof(data_len));
                data_len = data_len % 512;
                get_random(data, data_len);
                *(data + data_len) = 0;
                get_random(&iph->ip_id, sizeof(iph->ip_id));
                iph->ip_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
                iph->ip_sum = 0;
                iph->ip_sum = htons(csum((uint16_t *) buffer, ntohs(iph->ip_hl << 1)));
                udph->len = htons(sizeof(struct udphdr) + data_len);
                struct udpph uph;
                uph.udpph_src = iph->ip_src.s_addr;
                uph.udpph_dst = iph->ip_dst.s_addr;
                uph.udpph_zero = 0;
                uph.udpph_proto = iph->ip_p;
                uph.udpph_len = udph->len;
                udph->check = htons(csum2((uint16_t *) &uph, sizeof(uph) >> 1, (uint16_t *) data, (data_len + 1) >> 1));
                if (udph->check == 0)
                        udph->check = 0xffff;
                if (sendto(sd, buffer, ntohs(iph->ip_len), 0, (struct sockaddr *) &d_in, sizeof(d_in)) < 0) {
                        perror("sendto");
                        exit(EX_OSERR);
                }
        }
        close(sd);
        return 0;
}
