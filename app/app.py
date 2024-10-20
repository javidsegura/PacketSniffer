import streamlit as st
import pandas as pd
import time
import os
import signal

# Import your custom modules
from utils.packet_interpretation import filter_packets
from utils.packet_sender import send_packet
from utils.translate_hex import hex_to_string

def start_sniffer():
    os.system("../src/packet_sniffer &")

def stop_sniffer():
    os.system("pkill -f packet_sniffer")


def main():
    sniffer_enabled = True
    st.title("Packet Sniffer and Analyzer")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Start Packet Sniffer"):
            start_sniffer()
            st.success("Packet sniffer started!")
            sniffer_enabled = True 

    with col2:
        if st.button("Stop Packet Sniffer"):
            stop_sniffer()
            st.success("Packet sniffer stopped!")
            sniffer_enabled = False

    st.header("CSV Data")
    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Raw CSV Data")
        if not sniffer_enabled:
            try:
                df = pd.read_csv("../utils/PacketsResultsCSV.csv")
                st.dataframe(df.head())
            except FileNotFoundError:
                st.warning("An error occured: CSV file not found.")

    with col4:
        st.subheader("Filtered CSV Data")
        if not sniffer_enabled:
            filtered_df = filter_packets()
            print(filtered_df)
            st.dataframe(filtered_df)

    st.header("Send Packet")
    packet_data = st.text_input("Enter packet content:")
    if st.button("Send Packet"):
        result = send_packet(packet_data)
        st.write(result)

    st.header("Hex to String Translation")
    hex_input = st.text_input("Enter ID of the packet: ")
    if st.button("Translate"):
        translated = hex_to_string(hex_input)
        st.write(f"Translated string: {translated}")

if __name__ == "__main__":
    main()