""" Sends packet to a target IP and port"""

""" These needs to be implemeneted in C => refer to: https://www.geeksforgeeks.org/socket-programming-cc/ """

from scapy.all import *



def send_packet(src_ip:str, dest_ip:str, dest_port:int, payload:str = "hello world"):
    try:   
        src_ip = None 
        dest_ip = '10.192.67.245'
        dest_port = 80

        #Create IP layer
        ip = IP(dst=dest_ip, src=src_ip if src_ip else None)
        
        # Create a TCP layer with SYN flag set
        syn = TCP(dport=dest_port, flags='S')

        # Create the full packet
        packet = ip / syn

        # Send the SYN packet
        send(packet)

        # Wait for a short period to allow for SYN-ACK response (optional)
        time.sleep(1)

        # Custom payload as a binary string
        payload_data = payload.encode('utf-8')  # Convert string to binary

        # Create the TCP layer with the payload
        tcp = TCP(dport=dest_port, sport=RandShort(), flags='A', seq=1)

        # Create the full packet with the custom payload
        http_packet = ip / tcp / Raw(load=payload_data)

        # Send the HTTP packet
        send(http_packet)

        print(f"Packet sent from {src_ip} to {dest_ip} in port {dest_port}", type(src_ip), type(dest_ip), type(dest_port))

        return (f"Packet sent to {dest_ip}:{dest_port}")
    except Exception as e:
        return (f"Error sending packet: {e}")
    

    