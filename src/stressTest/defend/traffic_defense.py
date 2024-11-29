import psutil
import pandas as pd
import os

# Thresholds
MEMORY_USAGE_THRESHOLD = 80  # in percentage
PACKET_THRESHOLD = 100  # Packets per IP to trigger a warning
BAN_PACKET_THRESHOLD = 200  # Packets per IP to trigger an automatic ban

# Paths
PACKET_LOG_PATH = "../../other/PacketsResultsCSV.csv"
LOG_FILE_PATH = "../../other/DefenseLog.csv"

# Global Data Structures
TRAFFIC_LOG = {}
BANNED_IPS = set()

def monitor_memory():
    """
    Check system memory usage and flag if it exceeds the threshold.
    """
    memory = psutil.virtual_memory()
    if memory.percent > MEMORY_USAGE_THRESHOLD:
        print(f"⚠️ High memory usage detected: {memory.percent}%")
        log_defense_action("MEMORY WARNING", f"Memory usage at {memory.percent}%")

def monitor_traffic():
    """
    Analyze the packet log to detect suspicious traffic patterns.
    """
    global TRAFFIC_LOG
    if not os.path.exists(PACKET_LOG_PATH):
        print("⚠️ Packet log file not found. Skipping traffic analysis...")
        return

    try:
        # Read captured packets
        df = pd.read_csv(PACKET_LOG_PATH)

        # Analyze traffic
        TRAFFIC_LOG.clear()
        ip_counts = df['src_ip'].value_counts().to_dict()
        for ip, count in ip_counts.items():
            if ip in BANNED_IPS:
                continue  # Skip banned IPs
            TRAFFIC_LOG[ip] = count
            if count > BAN_PACKET_THRESHOLD:
                ban_ip(ip)
            elif count > PACKET_THRESHOLD:
                print(f"⚠️ Potential malicious traffic detected from {ip}: {count} packets")
                log_defense_action("TRAFFIC WARNING", f"{ip} sent {count} packets")
    except Exception as e:
        print(f"Error analyzing traffic: {e}")

def ban_ip(ip):
    """
    Ban an IP address and log the action.
    """
    print(f"🚫 Banning IP: {ip}")
    BANNED_IPS.add(ip)
    log_defense_action("BAN", f"IP {ip} banned for exceeding packet limit")

def log_defense_action(action, message):
    """
    Log a defense action to a file for future reference.
    """
    log_entry = {"action": action, "message": message}
    if not os.path.exists(LOG_FILE_PATH):
        # Create log file if it doesn't exist
        pd.DataFrame([log_entry]).to_csv(LOG_FILE_PATH, index=False)
    else:
        # Append to existing log
        existing_logs = pd.read_csv(LOG_FILE_PATH)
        updated_logs = pd.concat([existing_logs, pd.DataFrame([log_entry])], ignore_index=True)
        updated_logs.to_csv(LOG_FILE_PATH, index=False)

def defense_main():
    """
    Run the defense system checks (memory and traffic).
    """
    monitor_memory()
    monitor_traffic()
