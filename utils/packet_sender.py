from scapy.all import *

def send_http_request(target_ip, target_port):
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
    payload_data = "wassup nigga".encode('utf-8')  # Convert string to binary
    payload_length = len(payload_data)

    # Create the TCP layer with the payload
    tcp = TCP(dport=target_port, sport=RandShort(), flags='A', seq=1)

    # Create the full packet with the custom payload
    http_packet = ip / tcp / Raw(load=payload_data)

    # Send the HTTP packet
    print(f"Sending custom payload to {target_ip}:{target_port}")
    send(http_packet)

if __name__ == "__main__":
    target_ip = "10.192.67.245"  # Replace with your target IP address
    target_port = 80              # HTTP port
    send_http_request(target_ip, target_port)
