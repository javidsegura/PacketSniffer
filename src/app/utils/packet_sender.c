#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// Define the IP header
struct iphdr {
    unsigned char ihl : 4, version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

// Define the TCP header
struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned short doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

// Structure for pseudo header
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void send_packet(const char *src_ip, const char *dest_ip, int dest_port, const char *payload) {
    int sock;
    char packet[4096];
    struct sockaddr_in dest_addr;
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    struct pseudo_header psh;

    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set the socket option to include the IP header
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(sock);
        exit(1);
    }

    // Fill in the destination address
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        perror("Invalid destination IP address");
        close(sock);
        exit(1);
    }

    // Fill in the IP header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload));
    ip_header->id = htons(54321); // ID of this packet
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0; // Set to 0 before calculating checksum
    ip_header->saddr = inet_addr(src_ip);
    ip_header->daddr = dest_addr.sin_addr.s_addr;

    // Calculate IP checksum
    ip_header->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    // Fill in the TCP header
    tcp_header->source = htons(12345); // Source port
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5; // TCP header size
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840); // Maximum allowed window size
    tcp_header->check = 0; // Leave checksum 0 now, filled later by pseudo header
    tcp_header->urg_ptr = 0;

    // Copy payload
    strcpy(data, payload);

    // Fill in the pseudo header
    psh.source_address = inet_addr(src_ip);
    psh.dest_address = inet_addr(dest_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;

    // Calculate TCP checksum
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(payload);
    char *pseudogram = malloc(psize);
    if (pseudogram == NULL) {
        perror("Memory allocation failed");
        close(sock);
        exit(1);
    }
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr) + strlen(payload));
    tcp_header->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // Send the packet
    if (sendto(sock, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
    } else {
        printf("Packet sent successfully from %s to %s:%d\n", src_ip, dest_ip, dest_port);
    }

    close(sock);
}

int main() {
    const char *src_ip = "192.168.1.100";  // Replace with your source IP
    const char *dest_ip = "192.168.1.101"; // Replace with your destination IP
    int dest_port = 8080;                  // Replace with your destination port
    const char *payload = "hello world";   // Payload to send

    send_packet(src_ip, dest_ip, dest_port, payload);
    return 0;
}