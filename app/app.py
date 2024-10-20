""" UI for the packet sniffer"""

import streamlit as st
import pandas as pd
import os

# Import your custom modules
from utils.packet_interpretation import filter_packets
from utils.packet_sender import send_packet
from utils.translate_hex import hex_to_string

def start_sniffer():
    os.system("../src/packet_sniffer &")

def stop_sniffer():
    os.system("pkill -f packet_sniffer")


def main():
    # Keeping session variables on track
    if 'SNIFFER_RUNNING' not in st.session_state:
        st.session_state.SNIFFER_RUNNING = False 
    if 'JUST_STARTED' not in st.session_state:
        st.session_state.JUST_STARTED = True

    st.title("Packet Sniffer and Analyzer")

    col1, col2 = st.columns(2)

    # Starting and stopping the sniffer
    with col1:
        if st.button("Start Packet Sniffer"):
            st.session_state.SNIFFER_RUNNING = True 
            st.session_state.JUST_STARTED = False
            start_sniffer()
            st.success("Packet sniffer started!")

    with col2:
        if st.button("Stop Packet Sniffer"):
            if not st.session_state.SNIFFER_RUNNING:
                st.warning("Sniffer is already stopped")
            else:
                stop_sniffer()
                st.success("Sniffer has been stopped!")
                st.session_state.SNIFFER_RUNNING = False


    st.header("CSV Data")
    col3, col4 = st.columns(2)

    # Displaying all the captured packets
    with col3:
        st.subheader("Raw CSV Data")
        if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
            try:
                df = pd.read_csv("../utils/PacketsResultsCSV.csv")
                st.dataframe(df)
            except FileNotFoundError:
                st.warning("An error occured: CSV file not found.")

    # Displaying packets that were sent by the user
    with col4:
        st.subheader("Filtered CSV Data")
        if not st.session_state.SNIFFER_RUNNING and not st.session_state.JUST_STARTED:
            filtered_df = filter_packets()
            print(len(filtered_df))
            st.dataframe(filtered_df)

    # Sending packet
    st.header("Send Packet")
    packet_data = st.text_input("Enter packet content:")
    if st.button("Send Packet"):
        if not packet_data:
            st.warning("ERROR: No packet data input has been provided.")
        elif st.session_state.SNIFFER_RUNNING:
            try:
                result = send_packet(payload=str(packet_data))
                st.write(result)
            except Exception as e:
                st.warning(f"An error occured: {e}")
        else:
            st.warning("ERROR: Can't send packet if sniffer is not running.")

    # Reading payload
    st.header("Hex to String Translation")
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


if __name__ == "__main__":
    main()