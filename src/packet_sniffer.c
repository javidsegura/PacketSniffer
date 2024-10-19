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
    printf("Payload (%d bytes):\n", len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) { // Make rows of 16 elements 
            printf("\n");
        }
        printf("%02x ", payload[i]);  // Print in hex
        if (i == 20){
            printf("..........");
            break;
        }
    }
    printf("\n\n");
}

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

    // Cast the packet to Ethernet header
    eth_header = (struct ether_header *) packet;

    // 1) Print Ethernet header information
    printf("Ethernet Header:\n");
    printf("   Source MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_shost)); // either_ntoa transforms bit address into hex
    printf("   Destination MAC: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));
    
    // Check if the packet contains an IP packet (EtherType = 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // 2) Print IP header information
        printf("\nIP Header:\n");
        printf("   Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("   Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("   Protocol: %d\n", ip_header->ip_p);  // Protocol number (TCP = 6, UDP = 17)

        // 3) Categorizing the packet
        const char *category = "Unknown Packet";
        if (ip_header->ip_p == IPPROTO_TCP) {
            
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            printf("\nTCP Header:\n");
            printf("   Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("   Destination Port: %d\n", ntohs(tcp_header->th_dport));

            category = categorize_packet(ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), IPPROTO_TCP);

            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        
        } else if (ip_header->ip_p == IPPROTO_UDP) {
        
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            printf("\nUDP Header:\n");
            printf("   Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("   Destination Port: %d\n", ntohs(udp_header->uh_dport));

            category = categorize_packet(ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), IPPROTO_UDP);

            payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            category = "ICMP Packet (Ping/Traceroute)";
            // ICMP packets usually don't have a TCP or UDP header, so we skip to payload
            payload = packet + sizeof(struct ether_header) + sizeof(struct ip);
            payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip));
        }
        // Print category
        printf("   Packet Category: %s\n", category);

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

int main() {
    char *device;                        // Network device name to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];       // Array to store error message
    pcap_t *handle;                      // Struc with the capture session info 
    struct bpf_program fp;               // Structure with compiled packet filter
    char filter_exp[] = "ip";            // Filter on the network traffic
    bpf_u_int32 net;                     // IP address of the device
    bpf_u_int32 mask;                    // Subnet mask

    // 1) Get network interace. Returns name of network device suitable for pcap_create
    device = pcap_lookupdev(errbuf); // 
    if (device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
    printf("Sniffing on device named: %s\n", device);

    // 2) Get network info (IP and subnet mask). Writes to the passed integers. 
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf); // Writing to the assigned error buffer
        net = 0;
        mask = 0;
    }

    // 3) Open (a session on) the device for sniffing. Promiscuos mode HERE
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); /* 
     1 reprensents promiscuous mode (all packets in non-switched networks) 
     1000 represents the timeout (in miliseconds) to exit the listening for packets */
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 1;
    }

    // 4) Compile and apply a packet filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) { // Sending the compiled filter to the session
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 5) Capture packets in an infinite loop
    printf("Starting to capture packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, -1, packet_handler, NULL);  // The second paremeter represents number of pacakges to sniff 

    // 6) cleaning resources
    pcap_freecode(&fp); // Freeing allocated memory for struct
    pcap_close(handle); // Closing the session

    return 0;
}
