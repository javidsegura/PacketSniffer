
import streamlit as st
import subprocess

HOST_IP_ADDRESS = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip()) #or 10.192.67.245

def get_siderbar():
      st.metric("Local IP address", value=HOST_IP_ADDRESS)
