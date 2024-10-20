// Compile this with: 'gcc packet_sniffer.c -o packet_sniffer -lpcap'

#include <pcap.h>
#include <stdio.h>
#include "packet_handler.h"
#include "csv_funcs.h"

int main() {

    create_csv();
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
    while (1){
        pcap_loop(handle, 1, packet_handler, NULL);  // The second paremeter represents number of pacakges to sniff 
    };
    // 6) cleaning resources
    pcap_freecode(&fp); // Freeing allocated memory for struct
    pcap_close(handle); // Closing the session

    return 0;
}
