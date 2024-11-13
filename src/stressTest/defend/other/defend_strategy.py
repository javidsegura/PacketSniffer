import pandas as pd 
import streamlit as st
import matplotlib.pyplot as plt

def analyze_traffic():
      """
      If most percentage of traffic comes from the same IP, increase confidence.
      If most of the traffic from the prior hour has been sent from the same ip address you are under attack
      """

      path = "other/utils/PacketsResultsCSV.csv"
      df = pd.read_csv(path)

      # Filter through traffic of the last hour
      df['time_stamp'] = pd.to_datetime(df['time_stamp'])
      df_last_hour = df[df['time_stamp'] >= pd.Timestamp.now() - pd.Timedelta(hours=1)]

      if df_last_hour.empty:
            return False, None
      
      # Group by IP address and count the number of packets
      ip_counts = df_last_hour['src_ip'].value_counts()

      # Find the IP address with the most packets
      most_frequent_ip = ip_counts.idxmax()

      # Count how much traffic is coming from that IP
      traffic_from_ip = df_last_hour[df_last_hour['src_ip'] == most_frequent_ip]

      # Calculate the percentage of traffic from that IP
      percentage_traffic = (len(traffic_from_ip) / len(df_last_hour)) * 100

      if percentage_traffic < 50:
            return False, None

      # Compute how spread the traffic from the IP is
      # If the traffic is spread, it is not an attack, else it is.
      time_bins = pd.date_range(
        start=df_last_hour['time_stamp'].min(),
        end=df_last_hour['time_stamp'].max(),
        freq='5T'  # 5-minute intervals
      )

    
      # Count packets in each time bin
      traffic_distribution = pd.cut(
            traffic_from_ip['time_stamp'],
            bins=time_bins,
            labels=time_bins[:-1]
        ).value_counts().sort_index()
            

      variance = traffic_distribution.var()

      fig = traffic_distribution.plot().figure
      plt.title(f'Traffic Distribution from IP {most_frequent_ip}\nVariance: {variance:.2f}')
      plt.xticks(rotation=45)
      plt.tight_layout()  # This prevents label cutoff
      
      if variance < 2:
            return True, fig, most_frequent_ip
      else:
            return False, fig, None
      

      # Count how much percentage of that traffic came in the last 10mins