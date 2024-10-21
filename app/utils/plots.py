import pandas as pd
import plotly.express as px
from collections import Counter
import plotly.graph_objs as go


path = "/Users/javierdominguezsegura/Programming/College/Sophomore/Cprogramming/PacketSniffer/utils/PacketsResultsCSV.csv"

def time_graph(filter_by_ip=False, ip_address=None):

      """ IP address is address being tracked """
      df = pd.read_csv(path)

      if filter_by_ip:
            # Incoming
            df = df[df['dest_ip'] == ip_address]
  
      # Convert timestamp to datetime
      df['time_stamp'] = pd.to_datetime(df['time_stamp'])
                        
      # Create a new DataFrame with packet counts per timestamp
      packet_counts = df.groupby('time_stamp').size().reset_index(name='packet_count')
                        
      # Create the graph
      fig = px.line(packet_counts, x='time_stamp', y='packet_count', title="Packet traffic over time",
                                    labels={'time_stamp': 'Timestamp', 'packet_count': 'Number of Packets'})
                        
      # Customize the layout
      fig.update_layout(xaxis_title='Timestamp',
                                          yaxis_title='Number of Packets',
                                          hovermode='x unified')   

      return fig

def top_ips_graphs(filter_by_ip=False, ip_address=None):
    # Read the CSV file
    df = pd.read_csv(path)

    if filter_by_ip:
        # Incoming
        df = df[df['dest_ip'] == ip_address]
  
    # Count the occurrences of each source and destination IP
    src_ip_counts = Counter(df['src_ip'])
    dest_ip_counts = Counter(df['dest_ip'])

    # Get the top 3 source and destination IPs
    top_3_src = src_ip_counts.most_common(3)
    top_3_dest = dest_ip_counts.most_common(3)

    # Create the bar chart for top senders
    fig_senders = go.Figure(data=[
        go.Bar(name='Packets Sent', x=[ip for ip, _ in top_3_src], y=[count for _, count in top_3_src])
    ])

    # Customize the layout for senders
    fig_senders.update_layout(
        title='Top 3 IPs by Packets Sent',
        xaxis_title='IP Address',
        yaxis_title='Number of Packets Sent',
    )

    # Create the bar chart for top receivers
    fig_receivers = go.Figure(data=[
        go.Bar(name='Packets Received', x=[ip for ip, _ in top_3_dest], y=[count for _, count in top_3_dest])
    ])

    # Customize the layout for receivers
    fig_receivers.update_layout(
        title='Top 3 IPs by Packets Received',
        xaxis_title='IP Address',
        yaxis_title='Number of Packets Received',
    )

    return fig_senders, fig_receivers

def top_ports_graphs(ip_address):
    df = pd.read_csv(path)

    # Filter for incoming traffic to the specified IP address
    df = df[df['dest_ip'] == ip_address]

    # Count the occurrences of each destination port
    port_counts = Counter(df['dest_port'])

    # Get the top 3 destination ports
    top_3_ports = port_counts.most_common(3)

    # Create the pie chart for top ports
    fig_ports = go.Figure(data=[
        go.Pie(
            labels=[f"Port {port}" for port, _ in top_3_ports],
            values=[count for _, count in top_3_ports],
            hoverinfo='label+percent',
            textinfo='value'
        )
    ])

    # Customize the layout for ports
    fig_ports.update_layout(
        title=f'Top 3 Ports for Incoming Traffic to {ip_address}',
    )

    return fig_ports



