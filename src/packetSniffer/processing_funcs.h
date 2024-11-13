/* Includes auxiliary functions for packet handler */

#ifndef PROCESSING_FUNCS_H
#define PROCESSING_FUNCS_H 
#include <pcap.h>

// Function to categorize packets
char* categorize_packet(uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    /* Remove first parameter */
    if (protocol == IPPROTO_TCP) {
        if (dst_port == 80 || dst_port == 443) return "Web Traffic (HTTP/HTTPS)";
        if (dst_port == 25) return "Email (SMTP)";
        if (dst_port == 110) return "Email (POP3)";
        if (dst_port == 143) return "Email (IMAP)";
        if (dst_port == 21) return "File Transfer (FTP)";
        if (dst_port == 22) return "Secure Shell (SSH)";
        return "Other TCP Traffic";
    } else if (protocol == IPPROTO_UDP) {
        if (dst_port == 53) return "DNS Query";
        return "Other UDP Traffic";
    } else if (protocol == IPPROTO_ICMP) {
        return "ICMP Packet (Ping/Traceroute)";
    }
    return "Unknown Packet";
}

// Function to print payload data (content)
void print_payload(const u_char *payload, int len) {
    /*
    Prints array of binary elements. 
    */
    //printf("Payload (%d bytes):\n", len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) { // Make rows of 16 elements 
            //printf("\n");
        }
        //printf("%02x ", payload[i]);  // Print in hex
        if (i == 20){ // Limit payload print to stdout
            //printf("..........");
            break;
        }
    }
    //printf("\n\n");
}


#endif