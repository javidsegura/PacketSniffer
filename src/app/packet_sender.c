#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h> 


int send_packet(const char *src_ip, const char *dest_ip, int dest_port, const char *payload) {
    int sockfd;
    struct sockaddr_in dest_addr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Configure destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        perror("Invalid destination IP address");
        close(sockfd);
        return -1;
    }

    // Send packet
    if (sendto(sockfd, payload, strlen(payload), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Failed to send packet");
        close(sockfd);
        return -1;
    }

    printf("Packet sent successfully to %s:%d\n", dest_ip, dest_port);
    close(sockfd);
    return 0;
}
