#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int send_packet(const char *dest_ip, int dest_port, const char *payload) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("Socket creation error: %s\n", strerror(errno));
        return -1;
    }

    // Bind to the specific interface IP
    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(0);  // Let OS choose the port
    src_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        printf("Bind error: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    // Enable broadcast (optional, but helps ensure network interface usage)
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        printf("Setsockopt error: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    // Configure destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Send the packet
    ssize_t sent_bytes = sendto(sock, payload, strlen(payload), 0,
                               (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (sent_bytes < 0) {
        printf("Error sending packet: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    printf("Packet sent to %s:%d (%zd bytes)\n", dest_ip, dest_port, sent_bytes);
    close(sock);
    return 0;
}

int main() {
    // Remove root check as it's not needed for UDP sockets
    send_packet("10.192.67.245", 8080, "hello world");
    return 0;
}

