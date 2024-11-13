import streamlit as st
import subprocess

HOST_IP_ADDRESS = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip()) #or 10.192.67.245

def get_sidebar():
      st.metric("Local IP address", value=HOST_IP_ADDRESS)
      st.metric(f"Pointed IP address {"(" + st.session_state.IP_ADDRESS_POINTED_ALIAS  + ")" if st.session_state.IP_ADDRESS_POINTED_ALIAS != 'None' else ''}",
                 value=st.session_state.IP_ADDRESS_POINTED)
      st.metric("Port tracking", value=st.session_state.PORT_TRACKING)
      st.divider()
