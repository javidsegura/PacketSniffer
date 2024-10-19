#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// Packet handler function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;               // IP header structure
    struct ether_header *eth_header;    // Ethernet header structure
    
    // Cast the packet to Ethernet header
    eth_header = (struct ether_header *) packet;
    
    // Check if the packet contains an IP packet (EtherType = 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Cast packet to IP header (Skip Ethernet header)
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Print packet details
        printf("Packet length: %d bytes\n", pkthdr->len);
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Protocol: %d\n\n", ip_header->ip_p);  // Protocol number (TCP = 6, UDP = 17, etc.)
    }
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

    // Step 5: Capture packets in a loop
    pcap_loop(handle, 10, packet_handler, NULL);

    // Step 6: Clean up
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
