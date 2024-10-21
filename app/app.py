""" UI for the packet sniffer"""

import streamlit as st
import pandas as pd
import subprocess
import os
import pandas as pd

# Import your custom modules
from utils.packet_interpretation import self_sent_filter
from utils.packet_sender import send_packet
from utils.translate_hex import hex_to_string
from utils.plots import time_graph, top_ips_graphs, top_ports_graphs

def start_sniffer():
    os.system("../src/packet_sniffer &")

def stop_sniffer():
    os.system("pkill -f packet_sniffer")

HOST_IP_ADDRESS = ip_address = subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip() #or 10.192.67.245
PORT = 80
CAPTURED_PACKETS = 0


# Keeping session variables on track
if 'SNIFFER_RUNNING' not in st.session_state:
    st.session_state.SNIFFER_RUNNING = False 
if 'JUST_STARTED' not in st.session_state:
    st.session_state.JUST_STARTED = True
if 'IP_ADDRESS_TRACKING' not in st.session_state:
    st.session_state.IP_ADDRESS_TRACKING = str(HOST_IP_ADDRESS)
if 'PORT_TRACKING' not in st.session_state:
    st.session_state.PORT_TRACKING = 80



def main():

    st.set_page_config(page_title="Package Sniffer",layout="wide", page_icon="utils/imgs/favicon.png")
    st.title("Packet Sniffer and Analyzer")
    st.caption("A powerful tool for capturing, analyzing, and sending packets over your network")

    col1, col2 = st.columns(2, gap="medium")
    message_container = st.empty()
    st.divider()    

    # Defines section 1 (starting, stoping and displaying packets)
    with col1:
        btn1, btn2 = st.columns([.5,.5], gap="small")
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

        raw_csv_tab, sent_packets, filtered_packets = st.tabs(["All packets", "Sent packets", "Filtered packets"])
        with raw_csv_tab:
            if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
                try:
                    global CAPTURED_PACKETS
                    df = pd.read_csv("../utils/PacketsResultsCSV.csv")
                    CAPTURED_PACKETS = len(df)
                    st.dataframe(df)
                except FileNotFoundError:
                    st.warning("An error occured: CSV file not found.")
        
        with sent_packets:
            if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
                filtered_df = self_sent_filter()
                st.dataframe(filtered_df)
        
        if st.session_state.SNIFFER_RUNNING:
            st.markdown("""
            <div style="display: flex; justify-content: center;">
                <img src="https://media.tenor.com/On7kvXhzml4AAAAi/loading-gif.gif" alt="Alt Text" style="height: 120px;">
            </div>""", unsafe_allow_html=True)

            
    # Defines section 2 (sending, reading, metrics)
    with col2:
        col_send, col_read = st.columns(2)   
        with col_send:
            # Sending packet
            st.header("Send Packet")
            packet_data = st.text_input("Enter packet content:")
            if st.button("Send Packet"):
                if not packet_data:
                    st.warning("ERROR: No packet data input has been provided.")
                elif st.session_state.SNIFFER_RUNNING:
                    try:
                        result = send_packet(payload=packet_data)
                        st.write(result)
                    except Exception as e:
                        st.warning(f"An error occured: {e}")
                else:
                    st.warning("ERROR: Can't send packet if sniffer is not running.")

        with col_read:
            # Reading payload
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
                        st.warning("ERROR: ID not found or payload couldnt be translated")
                else:
                    st.warning("ERROR: Sniffer is still live or no packet has been yet captured.")
        
        st.divider()
        col_config, col_stats = st.columns(2)

        with col_config:
            st.metric(label="IP Tracking", value=st.session_state.IP_ADDRESS_TRACKING) # Tracking IP address
            st.metric(label="Port Tracking", value=st.session_state.PORT_TRACKING) # Tracking port
        with col_stats:
            st.metric(label="Packets Captured", value=CAPTURED_PACKETS)
            st.metric(label="Packets Sent", value=len(self_sent_filter()))
    

    # Sidebar settings
    st.sidebar.title("Settings")
    with st.sidebar:
        st.metric("Local IP: ", HOST_IP_ADDRESS)
        st.divider()
        st.header("Select ip address to track: ")
        ip_option = st.radio(
            "Choose IP address option:",
            ("Use host IP address", "Enter custom IP")
        )

        if ip_option == "Use host IP address":
            if st.session_state.IP_ADDRESS_TRACKING != HOST_IP_ADDRESS:
                st.session_state.IP_ADDRESS_TRACKING = str(HOST_IP_ADDRESS)
            st.success(f"Using host IP: {st.session_state.IP_ADDRESS_TRACKING}")
        else:
            custom_ip = st.text_input("Enter custom IP address:")
            if custom_ip != st.session_state.IP_ADDRESS_TRACKING:
                if custom_ip:
                    if st.button("Update IP Address"):
                        st.session_state.IP_ADDRESS_TRACKING = str(custom_ip)
                        st.success(f"IP Address updated to: {custom_ip}")
    

        st.header("Select port to track: ")
        st.write(f"Current port: {st.session_state.PORT_TRACKING}")
        customer_port = st.text_input("Enter customer port: ")
        if customer_port:
            st.session_state.PORT_TRACKING = int(customer_port)
            st.success(f"Port updated to: {customer_port}")

    # DDOS SECTIONS
    all_traffic, ip_traffic = st.tabs(["All traffic", f"IP-specific traffic ({st.session_state.IP_ADDRESS_TRACKING})"])
    if st.session_state.SNIFFER_RUNNING:
        st.write("Packet sniffer is running...")
    else:
        with all_traffic:
            if CAPTURED_PACKETS > 0:
                time_col, senders_col, receivers_col = st.columns(3)
                with time_col:
                    time_fig = time_graph()
                    st.plotly_chart(time_fig, use_container_width=True) 
                ips_fig = top_ips_graphs()
                with senders_col:
                    st.plotly_chart(ips_fig[0], use_container_width=True) 
                with receivers_col:
                    st.plotly_chart(ips_fig[1], use_container_width=True) 
            else:
                st.warning("No data available. Start the packet sniffer to capture packets.", icon=":material/warning:")
                
        with ip_traffic:
            if CAPTURED_PACKETS > 0:
                time_col, senders_col, ports_col = st.columns(3)
                with time_col:
                    time_fig = time_graph(filter_by_ip=True, ip_address=st.session_state.IP_ADDRESS_TRACKING)
                    st.plotly_chart(time_fig, use_container_width=True) 
                tracked_ips_fig = top_ips_graphs(filter_by_ip=True, ip_address=st.session_state.IP_ADDRESS_TRACKING)
                with senders_col:
                    st.plotly_chart(tracked_ips_fig[1], use_container_width=True) 
                with ports_col:
                    ports_fig = top_ports_graphs(ip_address=st.session_state.IP_ADDRESS_TRACKING)
                    st.plotly_chart(ports_fig, use_container_width=True) 
            else:
                st.warning("No data available. Start the packet sniffer to capture packets.", icon=":material/warning:")
            

        
       






if __name__ == "__main__":
    main()