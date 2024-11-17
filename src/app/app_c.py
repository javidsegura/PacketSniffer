""" UI for the packet sniffer """

import ctypes
import streamlit as st
import pandas as pd
import subprocess
import os
import pickle  # Ensure this is included for the Logistic Regression Model

st.set_page_config(page_title="Package Sniffer", layout="wide", page_icon="/imgs/favicon.png")

# Import your custom modules
from utils.packet_interpretation import self_sent_filter, filter_df, filter_df_with_features
from utils.translate_hex import hex_to_string
from sidebar import get_sidebar
from utils.session_state_vars import init_session_vars

# Load the compiled C library for packet sending
try:
    packet_sender = ctypes.CDLL('./packet_sender.so')  # Path to the compiled C shared library
    # Define the C function's argument and return types
    packet_sender.send_packet.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
    packet_sender.send_packet.restype = ctypes.c_int
except OSError as e:
    st.error(f"Error loading packet_sender.so: {e}")
    packet_sender = None

def send_packet(src_ip, dest_ip, dest_port, payload):
    """
    Calls the C implementation of send_packet.
    """
    if packet_sender is None:
        raise RuntimeError("C packet sender library not loaded.")

    # Convert Python strings to C-compatible strings
    c_src_ip = ctypes.c_char_p(src_ip.encode('utf-8'))
    c_dest_ip = ctypes.c_char_p(dest_ip.encode('utf-8'))
    c_dest_port = ctypes.c_int(dest_port)
    c_payload = ctypes.c_char_p(payload.encode('utf-8'))

    # Call the C function
    result = packet_sender.send_packet(c_src_ip, c_dest_ip, c_dest_port, c_payload)
    if result == 0:
        return "Packet sent successfully"
    else:
        raise RuntimeError(f"Failed to send packet with error code {result}")


# Logistic Regression Model
try:
    with open("logistic_model.pkl", "rb") as f:
        model = pickle.load(f)
except FileNotFoundError:
    model = None
    st.warning("Logistic regression model not found. Train the model first.")

def start_sniffer():
    os.system("../packetSniffer/bin/packet_sniffer &")

def stop_sniffer():
    os.system("pkill -f packet_sniffer")

def log_attack(ip, percentage, variance, packet_count):
    """
    Log detected attacks into a CSV file for retraining the model.
    """
    log_data = {
        'src_ip': [ip],
        'percentage_traffic': [percentage],
        'variance': [variance],
        'packet_count': [packet_count],
        'is_attack': [1]
    }
    log_df = pd.DataFrame(log_data)
    log_path = "../other/HistoricalTrafficData.csv"
    try:
        existing_logs = pd.read_csv(log_path)
        updated_logs = pd.concat([existing_logs, log_df], ignore_index=True)
        updated_logs.to_csv(log_path, index=False)
    except FileNotFoundError:
        log_df.to_csv(log_path, index=False)
    st.info(f"Attack from IP {ip} logged.")

def block_ip(ip):
    """
    Simulate blocking an IP address.
    """
    st.error(f"Blocking IP: {ip}")

def analyze_traffic_with_ml():
    """
    Analyze network traffic and predict potential DoS attacks using ML.
    """
    try:
        # Extract features from packet data
        feature_df = filter_df_with_features(src_ip="All", dest_ip="All", port=None)

        if model is not None:
            # Predict attacks using the logistic regression model
            X = feature_df[['percentage_traffic', 'variance', 'packet_count']]
            predictions = model.predict(X)
            feature_df['is_attack'] = predictions
        else:
            feature_df['is_attack'] = 0  # Default to no attack if model is missing

        return feature_df

    except Exception as e:
        st.error(f"Error analyzing traffic: {e}")
        return pd.DataFrame()

HOST_IP_ADDRESS = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip())  # Gets local IP address
PORT = "None"  # Default values

init_session_vars()

def main():
    st.title("Packet Sniffer and Analyzer")
    st.caption("A powerful tool for capturing, analyzing, and sending packets over your network")

    col1, col2 = st.columns(2, gap="medium")
    message_container = st.empty()
    st.divider()

    # Section 1 (Starting, Stopping, and Displaying Packets)
    with col1:
        btn1, btn2 = st.columns([.5, .5], gap="small")
        with btn1:
            if st.button("Start Packet Sniffer", type="primary", icon=":material/play_arrow:"):
                if not st.session_state.SNIFFER_RUNNING:
                    st.session_state.SNIFFER_RUNNING = True
                    st.session_state.JUST_STARTED = False
                    start_sniffer()
                    message_container.success("Packet sniffer started!", icon=":material/check_circle:")
                else:
                    message_container.warning("Sniffer is already running", icon=":material/warning:")

        with btn2:
            if st.button("Stop Packet Sniffer", icon=":material/pause:"):
                if st.session_state.SNIFFER_RUNNING:
                    stop_sniffer()
                    message_container.success("Sniffer has been stopped!", icon=":material/check_circle:")
                    st.session_state.SNIFFER_RUNNING = False
                else:
                    message_container.warning("Sniffer is already stopped", icon=":material/warning:")

    # Section 2 (Sending Packets via C Implementation)
    with col2:
        st.header("Send Packet")
        packet_data = st.text_input("Enter packet content:")
        if st.button("Send Packet"):
            if not packet_data:
                st.warning("ERROR: No packet data input has been provided.")
            elif st.session_state.SNIFFER_RUNNING:
                try:
                    result = send_packet(
                        src_ip=HOST_IP_ADDRESS,
                        dest_ip=st.session_state.IP_ADDRESS_POINTED,
                        dest_port=int(st.session_state.PORT_TRACKING),
                        payload=packet_data
                    )
                    st.success(result)
                except Exception as e:
                    st.warning(f"An error occurred: {e}")
            else:
                st.warning("ERROR: Can't send packet if sniffer is not running.")

if __name__ == "__main__":
    main()
