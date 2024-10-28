import streamlit as st
import subprocess


HOST_IP_ADDRESS = ip_address = subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip() #or 10.192.67.245

  
st.title("Settings app") 


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