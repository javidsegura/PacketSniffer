import streamlit as st
import subprocess
from sidebar import get_sidebar
import socket
import platform
import netifaces
import psutil
import requests 
import folium
from streamlit_folium import st_folium
from pages.utils.interfaces import get_friendly_interface_name

HOST_IP_ADDRESS = ip_address = subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip() #or 10.192.67.245

  
def settings_app():
    """ IDEA: Consider adding a confirmation button """
    st.title("Settings app") 

    ip_addr_col, port_col = st.columns(2)
    
    with ip_addr_col:
        st.header("Select IP address to track: ")
        customer_ip = st.text_input("Enter IP address to track: ", placeholder="XX.XXX.XX.XXX")
        if customer_ip == HOST_IP_ADDRESS:
            st.warning("ERROR: Can't track host IP address.")
        else:
            st.caption(f"Current tracked IP: {st.session_state.IP_ADDRESS_POINTED}")
            alias = st.text_input("Enter alias for IP: ", placeholder="my alias")
            if alias:
                st.session_state.IP_ADDRESS_POINTED_ALIAS = alias
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
    
    st.divider()

    # Network information section
    st.header("Network Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Geolocation")
        # Get hostname
        info_col1, info_col2 = st.columns(2)

        # Get public IP and location
        try:
            response = requests.get("https://ipinfo.io/json")
            if response.status_code == 200:
                data = response.json()

                with info_col1:
                    st.markdown("**System Info**")
                    st.markdown(f"🖥️ **Hostname:** {socket.gethostname()}")
                    st.markdown(f"🌐 **Public IP:** {data.get('ip', 'Unknown')}")
                    st.markdown(f"🏢 **ISP:** {data.get('org', 'Unknown')}")
                
                with info_col2:
                    st.markdown("**Location Info**")
                    st.markdown(f"🌍 **Country:** {data.get('country', 'Unknown')}")
                    st.markdown(f"🏙️ **City:** {data.get('city', 'Unknown')}")
                    st.markdown(f"📍 **Region:** {data.get('region', 'Unknown')}")
                    st.markdown(f"📮 **Postal:** {data.get('postal', 'Unknown')}")

                st.markdown("### Location Map")

                if 'data' in locals() and 'loc' in data:
                    lat, lon = map(float, data['loc'].split(','))
                    m = folium.Map(location=[lat, lon], zoom_start=10)
                    folium.Marker([lat, lon], tooltip="Your IP Location").add_to(m)
                    st.write("Geolocation Map:")
                    st_folium(m, width=400, height=300)
            else:
                st.warning("Unable to fetch location data.")
        except Exception as e:
            st.error(f"Error fetching location data: {str(e)}")
    with col2:
        st.subheader("Network Interfaces")
        network_interfaces = psutil.net_if_addrs()
        
        # Create an expander for each interface
        for interface, addresses in network_interfaces.items():
            # User friendly name of interface 
            friendly_name = get_friendly_interface_name(interface)

            with st.expander(f"Interface: {interface} ({friendly_name})"):
                # Create a formatted table-like display for each address
                for addr in addresses:
                    addr_type = addr.family.name if hasattr(addr.family, 'name') else str(addr.family)
                    st.markdown(f"**Address Type:** {addr_type}")
                    st.markdown("""
                    | Property | Value |
                    |----------|-------|
                    | Address | `{addr}` |
                    | Netmask | `{netmask}` |
                    | Broadcast | `{broadcast}` |
                    """.format(
                        addr=addr.address,
                        netmask=addr.netmask if addr.netmask else 'N/A',
                        broadcast=addr.broadcast if addr.broadcast else 'N/A'
                    ))
                    st.divider()

    with st.sidebar:
                get_sidebar()

settings_app()