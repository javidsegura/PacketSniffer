#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Function to categorize packets
const char* categorize_packet(uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
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
    printf("Payload (%d bytes):\n", len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", payload[i]);  // Print in hex
    }
    printf("\n\n");
}

// Packet handler function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;       // Ethernet header structure
    struct ip *ip_header;                  // IP header structure
    struct tcphdr *tcp_header;             // TCP header structure
    struct udphdr *udp_header;             // UDP header structure
    const u_char *payload;                 // Packet payload
    int payload_len = 0;                   // Payload length

    // Cast the packet to Ethernet header
    eth_header = (struct ether_header *) packet;

    // Print Ethernet header information
    printf("Ethernet Header:\n");
    printf("   Source MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
    printf("   Destination MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));
    
    // Check if the packet contains an IP packet (EtherType = 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Cast packet to IP header (Skip Ethernet header)
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Print IP header information
        printf("\nIP Header:\n");
        printf("   Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("   Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("   Protocol: %d\n", ip_header->ip_p);  // Protocol number (TCP = 6, UDP = 17)

        // Categorize the packet based on protocol
        const char *category = "Unknown Packet";
        if (ip_header->ip_p == IPPROTO_TCP) {
            // Cast to TCP header
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            // Print TCP header information
            printf("\nTCP Header:\n");
            printf("   Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("   Destination Port: %d\n", ntohs(tcp_header->th_dport));

            // Categorize the TCP packet
            category = categorize_packet(ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), IPPROTO_TCP);

            // Calculate the payload offset and length
            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // Cast to UDP header
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            // Print UDP header information
            printf("\nUDP Header:\n");
            printf("   Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("   Destination Port: %d\n", ntohs(udp_header->uh_dport));

            // Categorize the UDP packet
            category = categorize_packet(ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), IPPROTO_UDP);

            // Calculate the payload offset and length
            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            category = "ICMP Packet (Ping/Traceroute)";
            // ICMP packets usually don't have a TCP or UDP header, so we skip to payload
            payload = packet + sizeof(struct ether_header) + sizeof(struct ip);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip));
        }

        // Print category
        printf("   Category: %s\n", category);

        // Print the payload (if any)
        if (payload_len > 0) {
            print_payload(payload, payload_len);
        } else {
            printf("No payload data.\n");
        }
    } else {
        printf("Not an IP packet.\n");
    }
    printf("\n----------------------------------------------\n");
}

int main(int argc, char *argv[]) {
    char *dev;                          // Network device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];       // Error buffer
    pcap_t *handle;                      // Handle for capturing packets
    struct bpf_program fp;               // Compiled filter
    char filter_exp[] = "ip";            // Filter expression (e.g., "ip")
    bpf_u_int32 net;                     // IP address of the device
    bpf_u_int32 mask;                    // Subnet mask

    // Step 1: Find a device to sniff on
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    printf("Sniffing on device: %s\n", dev);

    // Step 2: Get network info (IP and subnet mask)
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Step 3: Open the device for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Step 4: Compile and apply a packet filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Step 5: Capture packets in an infinite loop
    printf("Starting to capture packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, 0, packet_handler, NULL);  // The '0' means to loop indefinitely

    // Step 6: Clean up (this will never be reached due to the infinite loop)
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
