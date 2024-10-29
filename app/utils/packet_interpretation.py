""" Finds the sent packet in the CSV file """
import pandas as pd

def self_sent_filter(src_ip:str, dest_ip:str, dest_port:int):
    try:
        df = pd.read_csv(".././utils/PacketsResultsCSV.csv")

        df = df[(df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip) & (df["dest_port"] == dest_port) & (df["payload"].isna() == False)]
        return df
    except Exception as e:
        return (f"Error filtering packets: {e}")
    
def filter_df(src_ip:str, dest_ip:str, port:str):
    try:
        df = pd.read_csv(".././utils/PacketsResultsCSV.csv")

        # Filter ip addresses
        df = df[(df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip)]
        # Filter through packets with content
        df = df[df["payload"].notna()]

        if port:
            df = df[df["dest_port"] == int(port)]

        return df
    except Exception as e:
        return (f"Error filtering packets: {e}")





