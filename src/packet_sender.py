from scapy.all import *

def send_http_request(target_ip, target_port):
    # Create an IP layer
    ip = IP(dst=target_ip)
    
    # Create a TCP layer with SYN flag set
    syn = TCP(dport=target_port, flags='S')

    # Create the full packet
    packet = ip / syn

    # Send the packet
    send(packet)

    # Create an HTTP GET request
    http_request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
    
    # Create the TCP layer with the HTTP request
    tcp = TCP(dport=target_port, sport=RandShort(), flags='A', seq=1)
    
    # Create the full HTTP packet
    http_packet = ip / tcp / Raw(load=http_request)

    # Send the HTTP packet
    send(http_packet)

if __name__ == "__main__":
    target_ip = "10.192.67.245"  # Replace with your target IP address
    target_port = 80            # HTTP port
    send_http_request(target_ip, target_port)
