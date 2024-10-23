""" Sends packet to a target IP and port"""

""" These needs to be implemeneted in C => refer to: https://www.geeksforgeeks.org/socket-programming-cc/ """

from scapy.all import *



def send_packet(target_ip:str ='10.192.67.245', target_port:int = 80, payload:str = "hello world"):
    try:
        # Create an IP layer
        ip = IP(dst=target_ip)
        
        # Create a TCP layer with SYN flag set
        syn = TCP(dport=target_port, flags='S')

        # Create the full packet
        packet = ip / syn

        # Send the SYN packet
        print(f"Sending SYN packet to {target_ip}:{target_port}")
        send(packet)

        # Wait for a short period to allow for SYN-ACK response (optional)
        time.sleep(1)

        # Custom payload as a binary string
        payload_data = payload.encode('utf-8')  # Convert string to binary

        # Create the TCP layer with the payload
        tcp = TCP(dport=target_port, sport=RandShort(), flags='A', seq=1)

        # Create the full packet with the custom payload
        http_packet = ip / tcp / Raw(load=payload_data)

        # Send the HTTP packet
        print(f"Sending custom payload to {target_ip}:{target_port}")
        send(http_packet)

        return (f"Packet sent to {target_ip}:{target_port}")
    except Exception as e:
        return (f"Error sending packet: {e}")
    

    