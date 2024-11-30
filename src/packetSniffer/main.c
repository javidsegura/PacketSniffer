/* Sets up the packet sniffer */

#include <pcap.h>
#include <stdio.h>
#include "packet_handler.h"
#include "csv_funcs.h"

int main() {
    create_csv();
    char *device = NULL;                 // Network device name to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];       // Array to store error message
    pcap_t *handle;                      // Structure with the capture session info
    struct bpf_program fp;               // Structure with compiled packet filter
    char filter_exp[] = "ip";            // Filter on the network traffic
    bpf_u_int32 net;                     // IP address of the device
    bpf_u_int32 mask;                    // Subnet mask
    pcap_if_t *alldevs, *dev;            // Struct to hold all devices
    
    // 1) Get list of available network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find devices: %s\n", errbuf);
        return 1;
    }

    // 2) Print all devices
    printf("Available devices:\n");
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("Device: %s", dev->name);
        if (dev->description)
            printf(" - %s", dev->description);
        printf("\n");
    }

    // 3) Select the first available device from the list
    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "No devices found.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    device = "en0"; // en0 is wireless internet network interface

    // 4) Get network info (IP and subnet mask) for the selected device
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf); // Writing to the assigned error buffer
        net = 0;
        mask = 0;
    }

    // 5) Open (a session on) the device for sniffing (Promiscuous mode)
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); /* 
        1 represents promiscuous mode (all packets in non-switched networks) 
        1000 represents the timeout (in milliseconds) to exit the listening for packets */
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 6) Compile and apply a packet filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 2;
    }
    // 6.5 Applying packet filter
    if (pcap_setfilter(handle, &fp) == -1) { // Sending the compiled filter to the session
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        pcap_close(handle);
        return 2;
    }

    // 7) Capture packets in an infinite loop
    printf("Starting to capture packets...\n");

    pcap_loop(handle, -1, packet_handler, NULL);  // The second parameter represents the number of packets to sniff 
    

    // 8) Clean resources
    pcap_freecode(&fp); // Freeing allocated memory for the filter struct
    pcap_close(handle); // Closing the session
    pcap_freealldevs(alldevs); // Free the list of devices

    return 0;
}
