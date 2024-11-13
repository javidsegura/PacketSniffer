import streamlit as st

PORT = "None" #default values

def init_session_vars():
    # Keeping session variables on track
    if 'SNIFFER_RUNNING' not in st.session_state:
        st.session_state.SNIFFER_RUNNING = False 
    if 'JUST_STARTED' not in st.session_state:
        st.session_state.JUST_STARTED = True

    # Tracking settings ssv
    if 'IP_ADDRESS_POINTED' not in st.session_state:
        st.session_state.IP_ADDRESS_POINTED = "None"
    if 'IP_ADDRESS_POINTED_ALIAS' not in st.session_state:
        st.session_state.IP_ADDRESS_POINTED_ALIAS = "None"
    if 'PORT_TRACKING' not in st.session_state:
        st.session_state.PORT_TRACKING = PORT

    # Packets ssv
    if 'CAPTURED_PACKETS' not in st.session_state:
        st.session_state.CAPTURED_PACKETS = 0
    if 'CAPT_PACKETS_DF' not in st.session_state:
        st.session_state.CAPT_PACKETS_DF = None

    # Filter csv ssv:
    if 'SRC_IP' not in st.session_state:
        st.session_state.SRC_IP = None
    if 'DEST_IP' not in st.session_state:
        st.session_state.DEST_IP = None
    if 'PORT' not in st.session_state:
        st.session_state.PORT = None