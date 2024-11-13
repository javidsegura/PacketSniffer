import streamlit as st
import docker
import time
import os
import subprocess

from other.defend_strategy import analyze_traffic

def start_sniffer():
    os.system("cd bin")
    st.write("Starting sniffer")
    os.system("./packet_sniffer &")

def stop_sniffer():
    st.write("Stopping sniffer")
    os.system("pkill -f packet_sniffer")

if not "START_ANALYSIS" in st.session_state:
    st.session_state.START_ANALYSIS = False


def get_container_memory_usage():
    client = docker.from_env()
    try:
        hostname = subprocess.check_output(['hostname'], text=True).strip()
        container = client.containers.get("ad5b0c1f74aa")  # Use current container ID instead of hardcoded name
        stats = container.stats(stream=False)
        
        # Calculate memory usage percentage
        memory_usage = stats['memory_stats']['usage']
        memory_limit = stats['memory_stats']['limit']
        memory_percentage = (memory_usage / memory_limit) * 100
        
        return round(memory_percentage, 2)
    except Exception as e:
        st.error(f"Error getting container stats: {e}")
        return None

def get_color_based_on_usage(percentage):
    if percentage >= 90:
        return "#FF0000"  # Red
    elif percentage >= 80:
        return "#FF3300"  # Red-Orange
    elif percentage >= 70:
        return "#FF6600"  # Dark Orange
    elif percentage >= 60:
        return "#FF9900"  # Orange
    elif percentage >= 50:
        return "#FFCC00"  # Orange-Yellow
    elif percentage >= 40:
        return "#FFFF00"  # Yellow
    elif percentage >= 30:
        return "#CCFF00"  # Yellow-Green
    elif percentage >= 20:
        return "#99FF00"  # Light Green
    elif percentage >= 10:
        return "#66FF00"  # Lime Green
    else:
        return "#33FF00"  # Green



def main():
    """ col1: Display an incrementing memory consumption packet on col1
        col2: is ddos detectiong algorithm
    """
    # Start the background thread if not already running

    st.title("WebApp Stats")

    start_btn, stop_btn = st.columns(2)
    with start_btn:
        btn_start_sniffer = st.button("Start Sniffer")
        if btn_start_sniffer:
            start_sniffer()
    with stop_btn:
        btn_stop_sniffer = st.button("Stop Sniffer")
        if btn_stop_sniffer:
            stop_sniffer()
    

    # Create placeholders for memory metrics
    metric_header = st.empty()
    metric_placeholder = st.empty()

    # Memory metrics update
    memory_percentage = get_container_memory_usage()
    if memory_percentage is not None:
        metric_header.header("Memory Usage:")
        color = get_color_based_on_usage(memory_percentage)
        metric_placeholder.markdown(
            f'<h1 style="color: {color};">{memory_percentage}%</h1>',
            unsafe_allow_html=True
        )
        if memory_percentage > 70:
            st.session_state.START_ANALYSIS = True
    else:
        st.error("Web app is not running")
    

    st.divider()
    
    analyze_container = st.button("Analyze")
    if st.session_state.START_ANALYSIS or analyze_container:
        os.system("bin/packet_sniffer &")

        # Conclude traffic analysis when approaching blackout
        os.system("kill $(pgrep packet_sniffer)")

        decision, plot, most_frequent_ip = analyze_traffic()
        if plot is not None:
            st.pyplot(plot)
        if decision:
            st.error("Attack detected")

            # Decise if user wants to bin ip_address
            st.write(f"Block attacker IP: {most_frequent_ip}?")
            if st.toggle('Block this IP address', key='block_ip'):
                st.error("🛡️ IP address has been blocked")
            else:
                st.success("✓ IP address remains unblocked")


        


    # Add here the blacklist => session state variable 
    # Add packets stats

    
main()


