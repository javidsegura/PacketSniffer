#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define PORT 8080

int main() {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);

    // Create UDP socket
    server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to en0 interface
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on %s:%d\n", inet_ntoa(server_addr.sin_addr), PORT);

    while (1) {
        // Receive packet
        ssize_t received_bytes = recvfrom(server_fd, buffer, BUFFER_SIZE, 0,
                                        (struct sockaddr*)&client_addr, &client_len);
        
        if (received_bytes < 0) {
            perror("Receive failed");
            continue;
        }

        // Null terminate the received data
        buffer[received_bytes] = '\0';

        // Print packet info
        printf("Received packet from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));
        printf("Data: %s\n", buffer);
        printf("Size: %zd bytes\n\n", received_bytes);
    }

    close(server_fd);
    return 0;
}