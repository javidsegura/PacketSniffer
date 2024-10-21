/* Auxiliary function that analyzes the content of a given captured packet */

#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include "processing_funcs.h"
#include "csv_funcs.h"

int PACKET_ID = 0;

// Packet handler function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    /*
    This is the callback function. Invoked every time pcap_loop sniffes a packet based on the configurations
    of the session handle. 
    Logs in stdout packets info

    Parameters:
        - user_data => unsigned char array with additional info
        - pkthdr => structure with metadata about the sniffed packet
        - packet => pointer to capture data about the packet (payload)
    */
    struct ether_header *eth_header;       // Ethernet header structure (who sent the data and to where)
    struct ip *ip_header;                  // IP header structure
    struct tcphdr *tcp_header;             // TCP header structure
    struct udphdr *udp_header;             // UDP header structure
    const u_char *payload;                 // Packet payload
    int payload_len = 0;                   // Payload length

    // 0) Adding package identifier
    add_int_to_csv(PACKET_ID++);
    
    // 1) Print and add the timestamp
    time_t raw_time = pkthdr->ts.tv_sec;   // Extract the seconds part of the timestamp
    struct tm *time_info = localtime(&raw_time);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);
    //printf("Timestamp: %s\n", timestamp);
    add_str_to_csv(timestamp);

    eth_header = (struct ether_header *) packet;

    // 2) Print Ethernet header information
    //printf("Ethernet Header:\n");
    char *src_mac = ether_ntoa((const struct ether_addr *)&eth_header->ether_shost);
    //printf("   Source MAC: %s\n", src_mac); // either_ntoa transforms bit address into hex
    add_str_to_csv(src_mac);

    char *dest_mac = ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost);
    //printf("   Destination MAC: %s\n", dest_mac);
    add_str_to_csv(dest_mac);

    // 3) Check if its an IP packet (and not an ARP packet)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // 4) Print IP header information
        char *src_ip = inet_ntoa(ip_header->ip_src);
        char *dest_ip = inet_ntoa(ip_header->ip_dst);
        //printf("\nIP Header:\n");
        //printf("   Source IP: %s\n", src_ip);
        add_str_to_csv(src_ip);
        //printf("   Destination IP: %s\n", dest_ip);
        add_str_to_csv(dest_ip);
        int protocol = ip_header->ip_p;
        

        // 5) Categorizing the packet
        char *category;
        if (protocol == IPPROTO_TCP) {

            //printf("   Protocol: TCP\n");  
            add_str_to_csv("TCP");
            
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            int src_port = ntohs(tcp_header->th_sport);
            int dest_port = ntohs(tcp_header->th_dport);
            //printf("\nTCP Header:\n");
            //printf("   Source Port: %d\n", src_port);
            //printf("   Destination Port: %d\n", dest_port);
            add_int_to_csv(src_port);
            add_int_to_csv(dest_port);

            category = categorize_packet(src_port, dest_port, IPPROTO_TCP);

            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        
        } else if (protocol == IPPROTO_UDP) {

            //printf("   Protocol: UDP\n");  
            add_str_to_csv("UDP");
        
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            int src_port = ntohs(udp_header->uh_sport);
            int dest_port = ntohs(udp_header->uh_dport);
            //printf("\nUDP Header:\n");
            //printf("   Source Port: %d\n", src_port);
            //printf("   Destination Port: %d\n", dest_port);
            add_int_to_csv(src_port);
            add_int_to_csv(dest_port);

            category = categorize_packet(src_port, dest_port, IPPROTO_UDP);

            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        
        }

        // Print and log the packet category
        //printf("   Packet Category: %s\n", category);
        add_str_to_csv(category);

        // Print the payload (if any)
        if (payload_len > 0) {
            print_payload(payload, payload_len);
            add_payload_csv(payload,payload_len);
        } else {
            //printf("No payload data.\n");
        }
    } else {
        //printf("Not an IP packet.\n");
        add_str_to_csv("Not an IP packet");
    }
    //printf("\n----------------------------------------------\n");
    new_line_csv();
    flush_csv();
}

#endif