import pandas as pd
import numpy as np

# Step 1: Generate synthetic packet-level data
np.random.seed(42)  # For reproducibility
num_packets = 10000
time_window = 3600  # 1 hour in seconds

data = {
    "packet_id": np.arange(1, num_packets + 1),
    "time_stamp": np.random.randint(0, time_window, num_packets),
    "src_mac": [f"00:1B:44:11:3A:{i:02X}" for i in np.random.randint(0, 256, num_packets)],
    "dest_mac": [f"00:1B:44:22:3B:{i:02X}" for i in np.random.randint(0, 256, num_packets)],
    "src_ip": [f"192.168.0.{i}" for i in np.random.randint(1, 255, num_packets)],
    "dest_ip": [f"192.168.1.{i}" for i in np.random.randint(1, 255, num_packets)],
    "protoc": np.random.choice(["TCP", "UDP", "ICMP"], num_packets),
    "src_port": np.random.randint(1024, 65535, num_packets),
    "dest_port": np.random.randint(1024, 65535, num_packets),
    "payload": np.random.randint(50, 1500, num_packets),
}

df = pd.DataFrame(data)

# Introduce attacker behavior
attack_src_ip = "192.168.0.100"
attack_dest_ip = "192.168.1.200"
num_attack_packets = int(num_packets * 0.1)

attack_data = pd.DataFrame({
    "packet_id": np.arange(num_packets + 1, num_packets + num_attack_packets + 1),
    "time_stamp": np.random.randint(0, 300, num_attack_packets),  # Within the first 5 minutes
    "src_mac": [f"00:1B:44:11:3A:DD"] * num_attack_packets,
    "dest_mac": [f"00:1B:44:22:3B:FF"] * num_attack_packets,
    "src_ip": [attack_src_ip] * num_attack_packets,
    "dest_ip": [attack_dest_ip] * num_attack_packets,
    "protoc": np.random.choice(["TCP", "UDP"], num_attack_packets),
    "src_port": np.random.randint(1024, 65535, num_attack_packets),
    "dest_port": np.random.randint(1024, 65535, num_attack_packets),
    "payload": np.random.randint(100, 1400, num_attack_packets),
})

df = pd.concat([df, attack_data]).reset_index(drop=True)

# Step 2: Aggregate to user-level metrics
aggregation = df.groupby("src_ip").agg(
    total_packets=("packet_id", "count"),
    unique_dest_ips=("dest_ip", "nunique"),
    avg_packets_per_min=("time_stamp", lambda x: len(x) / (time_window / 60)),
    packets_to_same_dest=("dest_ip", lambda x: x.value_counts().max()),
).reset_index()

# Step 3: Label the data
aggregation["attacker"] = np.where(
    (aggregation["src_ip"] == attack_src_ip) |
    (aggregation["packets_to_same_dest"] > 100), 1, 0
)

print(aggregation.head())

# Save to a CSV for logistic regression training
aggregation.to_csv("src/stressTest/defend/simulation/synthetic_ddos_data.csv", index=False)
