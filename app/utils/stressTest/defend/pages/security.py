import streamlit as st
import docker
import time
import os

#from utils.defend_strategy import analyze_traffic




def get_container_memory_usage():
    """
    Current error:
    File "/usr/local/lib/python3.11/site-packages/streamlit/runtime/scriptrunner/exec_code.py", line 88, in exec_func_with_error_handling
    result = func()
             ^^^^^^
File "/usr/local/lib/python3.11/site-packages/streamlit/runtime/scriptrunner/script_runner.py", line 579, in code_to_exec
    exec(code, module.__dict__)
File "/my_container/app/utils/stressTest/defend/pages/security.py", line 94, in <module>
    main()
File "/my_container/app/utils/stressTest/defend/pages/security.py", line 50, in main
    memory_percentage = get_container_memory_usage()
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/my_container/app/utils/stressTest/defend/pages/security.py", line 12, in get_container_memory_usage
    client = docker.from_env()
             ^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.11/site-packages/docker/client.py", line 94, in from_env
    return cls(
           ^^^^
File "/usr/local/lib/python3.11/site-packages/docker/client.py", line 45, in __init__
    self.api = APIClient(*args, **kwargs)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.11/site-packages/docker/api/client.py", line 207, in __init__
    self._version = self._retrieve_server_version()
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "/usr/local/lib/python3.11/site-packages/docker/api/client.py", line 230, in _retrieve_server_version
    raise DockerException("""
    client = docker.from_env()
    try:
        container = client.containers.get('myapp')
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
    elif percentage >= 75:
        return "#FFA500"  # Orange
    else:
        return "#FFD700"  # Yellow

def main():
    """ col1: Display an incrementing memory consumption packet on col1
        col2: is ddos detectiong algorithm
    """
    st.title("Docker Container Memory Usage")

    resourceUsage, attackDetection = st.columns(2)

    with resourceUsage:
        start_analysis = st.button("Start Analysis")
        # Create a placeholder for the metric
        metric_placeholder = st.empty()

        # Update every 2 seconds
        while start_analysis:
            memory_percentage = get_container_memory_usage()
            
            if memory_percentage is not None:
                color = get_color_based_on_usage(memory_percentage)
                metric_placeholder.markdown(
                f'<h1 style="color: {color};">{memory_percentage}%</h1>',
                unsafe_allow_html=True
            )
            else:
                st.error("Web app is not running")
                start_analysis = False
        
            time.sleep(2)
        stop_analysis = st.button("Stop Analysis")
        if stop_analysis:
            start_analysis = False
    
    st.divider()
    
    """with attackDetection:
        # Start analysis automatically if memory usage is greater than 60%
        if memory_percentage >=60:
            #os.system("src/packet_sniffer &") # not working
            ...

        # Conclude traffic analysis when approaching blackout
        if memory_percentage > 85:
            #os.system("kill $(pgrep packet_sniffer)")
            ...
        decision, plot = analyze_traffic()
        if decision:
            st.error("Attack detected")
        else:
            st.success("No attack detected")
        st.pyplot(plot)

        # BAN IP or TEMPORARILY BLOCK IP"""

        


    # Add here the blacklist => session state variable 

    
main()


