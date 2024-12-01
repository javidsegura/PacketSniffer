# ROLES
- Diego: sniffer
- Alex: sender


# 🌐 Network Packet Sniffer & Analyzer

A powerful network packet analysis tool with a user-friendly Streamlit interface that allows real-time packet capture, analysis, and transmission.

## Features

- **Real-time Packet Capture**: Monitor network traffic in real-time
- **Interactive Dashboard**: Built with Streamlit for easy visualization and control
- **Packet Analysis**:
  - View detailed packet information including source/destination IPs, ports, and payloads
  - Filter packets based on source IP, destination IP, and ports
  - Track sent packets and capture statistics
- **Packet Transmission**: Send custom packets to specified destinations
- **Payload Translation**: Convert hexadecimal payloads to readable strings
- **Metrics & Statistics**: Monitor captured and sent packet counts
- **Connection Test**: Test the connection to the pointed IP address
- **Logger**: Log per-session information

## 🚀 Installation

### Prerequisites
- Python 3.7+
- libpcap library
- GCC compiler

### Step 1: Clone the Repository
```bash
git clone https://github.com/javidsegura/PacketSniffer
```
### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Compile the C Code
```
make clean
make
```

### Step 4: Run the Streamlit App
```
streamlit run app.py
```

## 🛠️ Tech Stack

- **Frontend**: Streamlit
- **Backend**: Python, C
- **Packet Capture**: libpcap
- **Data Processing**: Pandas