""" UI for the packet sniffer """
import threading
import time
import streamlit as st
import pandas as pd
import subprocess
import os
import ctypes  # For integrating C shared libraries

# Import your custom modules
from utils.packet_interpretation import self_sent_filter, filter_df
from utils.translate_hex import hex_to_string
from sidebar import get_sidebar
from utils.session_state_vars import init_session_vars
from stressTest.defend.traffic_defense import defense_main  # Import defense system

# Path to the shared C library
PACKET_SENDER_LIB_PATH = os.path.join(os.path.dirname(__file__), "utils", "packet_sender.so")
packet_sender = ctypes.CDLL(PACKET_SENDER_LIB_PATH)

# Define the C function signature
packet_sender.send_packet.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
packet_sender.send_packet.restype = None

PATH = "../../other/PacketsResultsCSV.csv"

# Global variable to control the defense thread
DEFENSE_RUNNING = False

# Function to start the defense system in the background
def run_defense_system():
    while DEFENSE_RUNNING:
        try:
            defense_main()
        except Exception as e:
            st.warning(f"Defense system error: {e}")
        time.sleep(5)  # Check traffic every 5 seconds

def start_sniffer():
    os.system("./src/packetSniffer/bin/packet_sniffer &")

def stop_sniffer():
    os.system("pkill -f packet_sniffer")

def send_packet(src_ip: str, dest_ip: str, dest_port: int, payload: str = "hello world"):
    """
    Send packet using the C implementation.
    """
    try:
        packet_sender.send_packet(
            src_ip.encode("utf-8"),
            dest_ip.encode("utf-8"),
            dest_port,
            payload.encode("utf-8"),
        )
        st.success(f"Packet sent from {src_ip} to {dest_ip}:{dest_port}")
    except Exception as e:
        st.error(f"Error sending packet: {e}")


HOST_IP_ADDRESS = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip())  # Gets local IP addr
PORT = "None"  # default values

init_session_vars()

def main():
    global DEFENSE_RUNNING

    st.set_page_config(page_title="Package Sniffer", layout="wide", page_icon="./imgs/favicon.png")
    st.title("Packet Sniffer and Analyzer")
    st.caption("A powerful tool for capturing, analyzing, and sending packets over your network")

    col1, col2 = st.columns(2, gap="medium")
    message_container = st.empty()
    st.divider()

    # Defines section 1 (starting, stopping, and displaying packets)
    with col1:
        btn1, btn2 = st.columns([.5, .5], gap="small")
        with btn1:
            if st.button("Start Packet Sniffer", type="primary", icon=":material/play_arrow:"):
                if not st.session_state.SNIFFER_RUNNING:
                    st.session_state.SNIFFER_RUNNING = True
                    st.session_state.JUST_STARTED = False
                    start_sniffer()
                    message_container.success("Packet sniffer started!", icon=":material/check_circle:")

                    # Start the defense system in the background
                    DEFENSE_RUNNING = True
                    defense_thread = threading.Thread(target=run_defense_system, daemon=True)
                    defense_thread.start()

                else:
                    message_container.warning("Sniffer is already running", icon=":material/warning:")

        with btn2:
            if st.button("Stop Packet Sniffer", icon=":material/pause:"):
                if st.session_state.SNIFFER_RUNNING:
                    stop_sniffer()
                    message_container.success("Sniffer has been stopped!", icon=":material/check_circle:")
                    st.session_state.SNIFFER_RUNNING = False

                    # Stop the defense system
                    DEFENSE_RUNNING = False
                else:
                    message_container.warning("Sniffer is already stopped", icon=":material/warning:")

        raw_csv_tab, filtered_packets, auto_sent_packets = st.tabs(["All packets", "Filtered packets", "Sent packets"])
        with raw_csv_tab:
            if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
                try:
                    df = pd.read_csv(PATH)
                    st.session_state.CAPTURED_PACKETS = len(df)
                    st.session_state.CAPT_PACKETS_DF = df  # Restart when rerunning
                    st.dataframe(df)
                except FileNotFoundError:
                    st.warning("An error occurred: CSV file not found.")

        with auto_sent_packets:
            if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
                filtered_df = self_sent_filter(
                    src_ip=HOST_IP_ADDRESS,
                    dest_ip=st.session_state.IP_ADDRESS_POINTED,
                    dest_port=st.session_state.PORT_TRACKING,
                )
                st.dataframe(filtered_df)

        if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
            with filtered_packets:
                from_col, to_col, port_col = st.columns(3)
                with from_col:
                    st.markdown("SOURCE IP:")
                    default_value_src = f"{HOST_IP_ADDRESS}"
                    all_ip_addresses = list(st.session_state.CAPT_PACKETS_DF["src_ip"].unique())
                    all_ip_addresses.remove(HOST_IP_ADDRESS)
                    options = [ip_addr for ip_addr in all_ip_addresses]

                    use_default_src = st.checkbox(f"{default_value_src} (local)", value=True, key=2)
                    if use_default_src:
                        selected_option_src = default_value_src
                    else:
                        options.insert(0, "All")
                        selected_option_src = st.selectbox("Choose an option:", options, key=1)
                    st.session_state.SRC_IP = selected_option_src

                with to_col:
                    st.markdown("DESTINATION IP:")
                    default_value_dest = f"{st.session_state.IP_ADDRESS_POINTED}"
                    all_ip_addresses = list(st.session_state.CAPT_PACKETS_DF["dest_ip"].unique())
                    if st.session_state.IP_ADDRESS_POINTED in all_ip_addresses:
                        all_ip_addresses.remove(st.session_state.IP_ADDRESS_POINTED)
                    options = [ip_addr for ip_addr in all_ip_addresses]

                    use_default_dest = st.checkbox(f"{default_value_dest} (pointed)", value=True, key=3)
                    if use_default_dest:
                        selected_option_dest = default_value_dest
                    else:
                        options.insert(0, "All")
                        selected_option_dest = st.selectbox("Choose an option:", options, key=4)
                    st.session_state.DEST_IP = selected_option_dest

                with port_col:
                    default_value_port = f"{PORT}"
                    use_default_port = st.radio("PORT:", options=["All", f"Default ({PORT})", "Other"], key=5)
                    if use_default_port == f"Default ({PORT})":
                        selected_option_port = default_value_port
                    elif use_default_port == f"Other":
                        selected_option_port = st.text_input(label="Your port", placeholder="Choose an option:", key=6)
                    else:
                        selected_option_port = None
                    st.session_state.PORT = selected_option_port

                filter_csv_btn = st.button("Filter CSV")
                if filter_csv_btn:
                    filtered_csv = filter_df(st.session_state.SRC_IP, st.session_state.DEST_IP, st.session_state.PORT)
                    st.dataframe(filtered_csv)

        if st.session_state.SNIFFER_RUNNING:
            st.markdown(
                """
                <div style="display: flex; justify-content: center;">
                    <img src="https://media.tenor.com/On7kvXhzml4AAAAi/loading-gif.gif" alt="Alt Text" style="height: 120px;">
                </div>""",
                unsafe_allow_html=True,
            )

    # Defines section 2 (sending, reading, metrics)
    with col2:
        col_send, col_read = st.columns(2)
        with col_send:
            st.header("Send Packet")
            packet_data = st.text_input("Enter packet content:")
            if st.button("Send Packet"):
                if not packet_data:
                    st.warning("ERROR: No packet data input has been provided.")
                elif st.session_state.SNIFFER_RUNNING:
                    try:
                        send_packet(
                            src_ip=HOST_IP_ADDRESS,
                            dest_ip=st.session_state.IP_ADDRESS_POINTED,
                            dest_port=st.session_state.PORT_TRACKING,
                            payload=packet_data,
                        )
                    except Exception as e:
                        st.warning(f"An error occurred: {e}")
                else:
                    st.warning("ERROR: Can't send packet if sniffer is not running.")

        with col_read:
            st.header("Read Packet")
            record_id = st.text_input("Enter ID of the packet: ")
            if st.button("Translate"):
                if not record_id:
                    st.warning("ERROR: No ID input has been provided.")
                elif not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED and record_id:
                    translated = hex_to_string(int(record_id))
                    if translated != -1:
                        st.write(f"Packet content: {translated}")
                    else:
                        st.warning("ERROR: ID not found or payload couldn't be translated.")
                else:
                    st.warning("ERROR: Sniffer is still live or no packet has been yet captured.")

        st.divider()
        col_config, col_stats = st.columns(2)

        with col_config:
            if st.session_state.IP_ADDRESS_POINTED == HOST_IP_ADDRESS:
                ip_type = "(local)"
            else:
                ip_type = f"({st.session_state.IP_ADDRESS_POINTED_ALIAS if st.session_state.IP_ADDRESS_POINTED_ALIAS != 'None' else 'other'})"
            st.metric(label=f"IP Tracking {ip_type}", value=st.session_state.IP_ADDRESS_POINTED)  # Tracking IP address
            st.metric(label="Port Tracking", value=st.session_state.PORT_TRACKING)  # Tracking port
        with col_stats:
            st.metric(label="Packets Captured", value=st.session_state.CAPTURED_PACKETS)
            st.metric(label="Packets Sent", value=len(self_sent_filter(src_ip=HOST_IP_ADDRESS, dest_ip=st.session_state.IP_ADDRESS_POINTED, dest_port=st.session_state.PORT_TRACKING)))

    with st.sidebar:
        get_sidebar()


if __name__ == "__main__":
    main()
