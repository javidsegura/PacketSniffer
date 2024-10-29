import streamlit as st
import subprocess


HOST_IP_ADDRESS = ip_address = subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip() #or 10.192.67.245

  
def settings_app():
    """ IDEA: Consider adding a confirmation button """
    st.title("Settings app") 

    ip_addr_col, port_col = st.columns(2)
    
    with ip_addr_col:
        st.header("Select IP address to track: ")
        customer_ip = st.text_input("Enter IP address to track: ", placeholder="XX.XXX.XX.XXX")
        st.caption(f"Current tracked IP: {st.session_state.IP_ADDRESS_POINTED}")
        ip_confirm_btn = st.button("Confirm")
        if ip_confirm_btn and customer_ip:
                    st.session_state.IP_ADDRESS_POINTED = str(customer_ip)
                    st.success(f"IP updated succesfully to {st.session_state.IP_ADDRESS_POINTED}")
        
    with port_col:
        st.header("Select port to track: ")
        customer_port = st.text_input("Enter customer port: ", placeholder="8080")
        st.caption(f"Current port: {st.session_state.PORT_TRACKING}")
        port_confirm_btn = st.button("Confirm", key = 2)
        if port_confirm_btn and customer_port:
                    st.session_state.PORT_TRACKING = int(customer_port)
                    st.success(f"Port updated succesfully to {st.session_state.PORT_TRACKING}")


    

    with st.sidebar:
                st.metric("Local IP address", value=HOST_IP_ADDRESS)

settings_app()