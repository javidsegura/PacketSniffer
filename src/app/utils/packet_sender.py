""" THESE MODULES BELONGS TO THE ORIGINAL DEMO. Its deprecated."""

""" These needs to be implemeneted in C => refer to: https://www.geeksforgeeks.org/socket-programming-cc/ """

from scapy.all import *

def send_packet(dest_ip: str, dest_port: int, payload: str = "hello world"):
    try:

        if dest_port == "None":
            raise ValueError("Destination port is required")
        
        # Set up IP and TCP layers
        ip = IP(dst=dest_ip)
        
        # Send SYN packet
        syn = TCP(dport=dest_port, flags='S')
        send(ip/syn)

        # Wait for potential SYN-ACK response
        time.sleep(1)

        # Custom payload as a binary string
        payload_data = payload.encode('utf-8') 

        # Send packet with payload after ACK
        tcp = TCP(dport=dest_port, sport=RandShort(), flags='A', seq=1)
        http_packet = ip / tcp / Raw(load=payload_data)

        # Send HTTP packet
        send(http_packet)

        print(f"Packet sent to {dest_ip}:{dest_port}")
        return (f"Packet sent to {dest_ip}:{dest_port}")

    except Exception as e:
        return (f"Error sending packet: {e}")

