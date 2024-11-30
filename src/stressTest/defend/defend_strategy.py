import pandas as pd 
import streamlit as st
#import matplotlib.pyplot as plt
import os
import subprocess

HOST_IP = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip()) # Gets local IP addrs

class DefendStrategy:
      def __init__(self):
            pass

      def analyze_traffic(self) -> tuple[bool, str]:
            """ Returns [under attack, ip address attacker] """

            path = "../../other/PacketsResultsCSV.csv"
            df = pd.read_csv(path)

            # Clean dataset. Only keep non-local traffic and traffic sent to local ip address
            df = df[df["src_ip"] != HOST_IP]
            df = df[df["dest_ip"] == HOST_IP]

            # Get ip address that has sent the msot
            ip_counts = df["src_ip"].value_counts()
            
            # Most frequent ip address
            most_frequent_ip = ip_counts.idxmax()

            print("IP counts: ", ip_counts)
            print("Most frequent ip: ", most_frequent_ip)
            print("Ratio: ", ip_counts[most_frequent_ip] / len(df))

            # If most_frequent_ip has sent disproportionate amount of traffic, then we are under attack
            if ip_counts[most_frequent_ip] / len(df) > 0.2:
                  return True, most_frequent_ip
            else:
                  return False, None

      def ban_ip(self, ip: str):
            """Bans an IP address on macOS using pfctl"""
            try:
                  script_path = os.path.join(os.path.dirname(__file__), "../scripts/firewall_manager.sh")
                  subprocess.run(['bash', script_path, 'ban', ip], check=True)
                  return True
            except subprocess.CalledProcessError as e:
                  print(f"Failed to ban IP: {e}")
                  return False
        
      def unban_ip(self, ip: str):
            """Unbans an IP address on macOS using pfctl"""
            try:
                  script_path = os.path.join(os.path.dirname(__file__), "../scripts/firewall_manager.sh")
                  subprocess.run(['bash', script_path, 'unban', ip], check=True)
                  return True
            except subprocess.CalledProcessError as e:
                  print(f"Failed to unban IP: {e}")
                  return False
      
