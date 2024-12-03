import streamlit as st
import subprocess

HOST_IP_ADDRESS = str(subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip()) #or 10.192.67.245

def get_sidebar():
      st.metric("Local IP address", value=HOST_IP_ADDRESS)
      pointed_ip_label = f"Pointed IP address {"(" + st.session_state.IP_ADDRESS_POINTED_ALIAS  + ")" 
                                               if st.session_state.IP_ADDRESS_POINTED_ALIAS != 'None' else ''}"
      st.metric(label=pointed_ip_label, value=st.session_state.IP_ADDRESS_POINTED)
      
      st.metric("Port tracking", value=st.session_state.PORT_TRACKING)
      st.divider()

      if st.session_state.IP_ADDRESS_POINTED != 'None':
            if st.button("Test Connection"):
                  try:
                        # Running ping command toward the pointed IP address
                        response = subprocess.run(['ping', '-c', '1',  
                                                st.session_state.IP_ADDRESS_POINTED],   
                                                capture_output=True, text=True)
                        st.write(f"Ping test to {st.session_state.IP_ADDRESS_POINTED}:")
                        st.code(response.stdout)
                  except Exception as e:
                        st.error(f"Ping test failed: {str(e)}")
