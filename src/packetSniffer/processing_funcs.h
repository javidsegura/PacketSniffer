/* Includes auxiliary functions for packet handler */

#ifndef PROCESSING_FUNCS_H
#define PROCESSING_FUNCS_H 

#include <pcap.h>
#include <stdint.h>

// Function to categorize packets
const char* categorize_packet(uint16_t src_port, uint16_t dest_port, uint8_t protocol) {
    if (protocol == IPPROTO_TCP) {
        // Check if the source or destination port matches specific categories
        if (src_port == 20 || dest_port == 20) return "FTP";
        if (src_port == 21 || dest_port == 21) return "FTP";
        if (src_port == 22 || dest_port == 22) return "SSH";
        if (src_port == 23 || dest_port == 23) return "Telnet";
        if (src_port == 25 || dest_port == 25) return "SMTP";
        if (src_port == 53 || dest_port == 53) return "DNS";
        if (src_port == 67 || dest_port == 67) return "DHCP";
        if (src_port == 68 || dest_port == 68) return "DHCP";
        if (src_port == 80 || dest_port == 80) return "HTTP";
        if (src_port == 110 || dest_port == 110) return "POP3";
        if (src_port == 119 || dest_port == 119) return "NNTP";
        if (src_port == 123 || dest_port == 123) return "NTP";
        if (src_port == 143 || dest_port == 143) return "IMAP";
        if (src_port == 161 || dest_port == 161) return "SNMP";
        if (src_port == 162 || dest_port == 162) return "SNMP";
        if (src_port == 443 || dest_port == 443) return "HTTPS";
        if (src_port == 465 || dest_port == 465) return "SMTPS";
        if (src_port == 514 || dest_port == 514) return "Syslog";
        if (src_port == 631 || dest_port == 631) return "IPP";
        if (src_port == 993 || dest_port == 993) return "IMAPS";
        if (src_port == 995 || dest_port == 995) return "POP3S";
        if (src_port == 990 || dest_port == 990) return "FTPS";
        if (src_port == 1234 || dest_port == 1234) return "Qtel";
        if (src_port == 5000 || dest_port == 5000) return "UPnP";
        if (src_port == 5222 || dest_port == 5222) return "XMPP";
        if (src_port == 5223 || dest_port == 5223) return "XMPP";
        if (src_port == 5900 || dest_port == 5900) return "VNC";
        if (src_port == 5984 || dest_port == 5984) return "CouchDB";
        if (src_port == 6000 || dest_port == 6000) return "X11";
        if (src_port == 6379 || dest_port == 6379) return "Redis";
        if (src_port == 6666 || dest_port == 6666) return "Doom";
        if (src_port == 8000 || dest_port == 8000) return "HTTP-ALT";
        if (src_port == 8080 || dest_port == 8080) return "HTTP-ALT";
        if (src_port == 8443 || dest_port == 8443) return "HTTPS-ALT";
        if (src_port == 27017 || dest_port == 27017) return "MongoDB";
        if (src_port == 3306 || dest_port == 3306) return "MySQL";
        if (src_port == 1433 || dest_port == 1433) return "MSSQL";
        if (src_port == 1521 || dest_port == 1521) return "Oracle";
        if (src_port == 3389 || dest_port == 3389) return "RDP";
        if (src_port == 50000 || dest_port == 50000) return "SAP";
        if (src_port == 49152 || dest_port == 49152) return "Dynamic/Private";
        return "Other TCP Traffic";
    } else if (protocol == IPPROTO_UDP) {
        if (dest_port == 53) return "DNS Query";
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
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            // Print new row every 16 bytes
        }
        // Print in hex format
        if (i == 20) {
            // Limit payload print to 20 bytes
            break;
        }
    }
}

#endif
