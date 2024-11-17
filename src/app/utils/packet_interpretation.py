import pandas as pd
import os 

PATH = "/other/PacketsResultsCSV.csv"

def self_sent_filter(src_ip: str, dest_ip: str, dest_port: int):
    """
    Filters packets sent from the specified source IP to the destination IP and port.
    """
    try:
        df = pd.read_csv(PATH)
        filtered_df = df[
            (df["src_ip"] == src_ip) &
            (df["dest_ip"] == dest_ip) &
            (df["dest_port"] == dest_port) &
            (df["payload"].notna())
        ]
        return filtered_df
    except FileNotFoundError:
        raise FileNotFoundError(f"CSV file not found at path: {PATH}")
    except Exception as e:
        raise ValueError(f"Error filtering packets with self_sent_filter: {e}")

def filter_df(src_ip: str, dest_ip: str, port: str):
    """
    Filters packets based on source IP, destination IP, and port.
    """
    try:
        df = pd.read_csv(PATH)

        if src_ip == "All" and dest_ip == "All":
            return df
        if dest_ip == "All":
            filtered_df = df[df["src_ip"] == src_ip]
        elif src_ip == "All":
            filtered_df = df[df["dest_ip"] == dest_ip]
        else:
            filtered_df = df[
                (df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip)
            ]

        # Filter packets with content
        filtered_df = filtered_df[filtered_df["payload"].notna()]

        # Filter by port if specified
        if port:
            filtered_df = filtered_df[filtered_df["dest_port"] == int(port)]

        return filtered_df

    except FileNotFoundError:
        raise FileNotFoundError(f"CSV file not found at path: {PATH}")
    except Exception as e:
        raise ValueError(f"Error filtering packets with filter_df: {e}")


def filter_df_with_features(src_ip: str, dest_ip: str, port: str):
    try:
        df = pd.read_csv(PATH)

        if src_ip == "All" and dest_ip == "All":
            filtered_df = df
        elif dest_ip == "All":
            filtered_df = df[(df["src_ip"] == src_ip)]
        elif src_ip == "All":
            filtered_df = df[(df["dest_ip"] == dest_ip)]
        else:
            filtered_df = df[(df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip)]

        # Filter through packets with content
        filtered_df = filtered_df[filtered_df["payload"].notna()]

        if port:
            filtered_df = filtered_df[filtered_df["dest_port"] == int(port)]

        # Feature extraction for traffic analysis
        feature_data = []
        ip_counts = filtered_df['src_ip'].value_counts()
        for ip, count in ip_counts.items():
            ip_traffic = filtered_df[filtered_df['src_ip'] == ip]
            percentage_traffic = (count / len(filtered_df)) * 100

            # Analyze traffic spread over time
            filtered_df['time_stamp'] = pd.to_datetime(filtered_df['time_stamp'])
            time_bins = pd.date_range(
                start=filtered_df['time_stamp'].min(),
                end=filtered_df['time_stamp'].max(),
                freq='5T'  # 5-minute intervals
            )
            traffic_distribution = pd.cut(
                ip_traffic['time_stamp'],
                bins=time_bins,
                labels=time_bins[:-1]
            ).value_counts().sort_index()
            variance = traffic_distribution.var()

            feature_data.append({
                "src_ip": ip,
                "percentage_traffic": percentage_traffic,
                "variance": variance,
                "packet_count": count
            })

        feature_df = pd.DataFrame(feature_data)
        return feature_df

    except Exception as e:
        return (f"Error filtering packets and extracting features: {e}")
