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

char *categorize_port(int port) {
    switch (port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 68: return "DHCP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 119: return "NNTP";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 162: return "SNMP";
        case 443: return "HTTPS";
        case 465: return "SMTPS";
        case 514: return "Syslog";
        case 631: return "IPP";
        case 990: return "FTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1234: return "Qtel";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5000: return "UPnP";
        case 5223: return "XMPP";
        case 5900: return "VNC";
        case 5984: return "CouchDB";
        case 6000: return "X11";
        case 6379: return "Redis";
        case 6666: return "Doom";
        case 8080: return "HTTP-ALT";
        case 8443: return "HTTPS-ALT";
        case 27017: return "MongoDB";
        case 49152: return "Dynamic/Private";
        case 50000: return "SAP";
        default: return "Unknown";
    }
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