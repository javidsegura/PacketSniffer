import streamlit as st
from utils.plots import time_graph, top_ips_graphs, top_ports_graphs
import subprocess
from sidebar import get_sidebar


HOST_IP_ADDRESS = ip_address = subprocess.check_output(['ipconfig', 'getifaddr', 'en0']).decode('utf-8').strip() #or 10.192.67.245

def stats_app():
    st.title("Stats section") 

    # DDOS SECTIONS
    all_traffic, ip_traffic = st.tabs(["All traffic", f"IP-specific traffic ({st.session_state.IP_ADDRESS_POINTED}) {"(" + st.session_state.IP_ADDRESS_POINTED_ALIAS + ")" if st.session_state.IP_ADDRESS_POINTED_ALIAS != 'None' else ''}"])
    if st.session_state.SNIFFER_RUNNING:
            st.write("Packet sniffer is running...")
    else:
        with all_traffic:
                if st.session_state.CAPTURED_PACKETS > 0:
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
                    st.warning("No data available. Start the packet sniffer to capture packets.") #, icon=":material/warning:")
                    
        with ip_traffic:
                if st.session_state.CAPTURED_PACKETS > 0:
                    time_col, senders_col, ports_col = st.columns(3)
                    with time_col:
                        time_fig = time_graph(filter_by_ip=True, ip_address=st.session_state.IP_ADDRESS_POINTED)
                        st.plotly_chart(time_fig, use_container_width=True) 
                    tracked_ips_fig = top_ips_graphs(filter_by_ip=True, ip_address=st.session_state.IP_ADDRESS_POINTED)
                    with senders_col:
                        st.plotly_chart(tracked_ips_fig[1], use_container_width=True) 
                    with ports_col:
                        ports_fig = top_ports_graphs(ip_address=st.session_state.IP_ADDRESS_POINTED)
                        st.plotly_chart(ports_fig, use_container_width=True) 
                else:
                    st.warning("No data available. Start the packet sniffer to capture packets.")# , icon=":material/warning:")

    with st.sidebar:
            get_sidebar()


stats_app()