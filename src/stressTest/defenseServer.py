from flask import Flask
import subprocess
import os
import time
import threading
import signal
from defend.defend_strategy import DefendStrategy


app = Flask(__name__)


@app.route('/trigger-defense', methods=['POST'])
def trigger_defense():
    def host_function():
        # Analyze network traffic
        os.system("pwd")
        
        # Start packet sniffer as a subprocess
        process = subprocess.Popen(['./bin/packet_sniffer'])
        
        # Wait for 10 seconds
        time.sleep(5)
        
        # Terminate the process
        process.terminate()
        process.wait()  # Wait for the process to actually terminate

        print("Analyzing the traffic")
        os.system("pwd")

        # Start analyzing the traffic
        defense = DefendStrategy()
        under_attack, ip = defense.analyze_traffic()

        if under_attack:
              defense.ban_ip(ip)
              
              

        
        return "Defense activated..."
    
    return host_function()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=12345)