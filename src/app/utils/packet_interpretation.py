""" Finds the sent packet in the CSV file """
import pandas as pd

PATH = "../../other/PacketsResultsCSV.csv"

def self_sent_filter(src_ip:str, dest_ip:str, dest_port:int):
    try:
        df = pd.read_csv(PATH)

        df = df[(df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip) & (df["dest_port"] == dest_port) & (df["payload"].isna() == False)]
        return df
    except Exception as e:
        return (f"Error filtering packets: {e}")
    
def filter_df(src_ip:str, dest_ip:str, port:str):
    try:
        df = pd.read_csv(PATH)

        if src_ip == "All" and dest_ip == "All":
            return df
        if dest_ip == "All":
            df = df[(df["src_ip"] == src_ip)]
        elif src_ip == "All":
            df = df[(df["dest_ip"] == dest_ip)]
        else:
            df = df[(df["src_ip"] == src_ip) & (df["dest_ip"] == dest_ip)]
            
        # Filter through packets with content
        df = df[df["payload"].notna()]

        if port:
            df = df[df["dest_port"] == int(port)]
        return df
    
    except Exception as e:
        return (f"Error filtering packets: {e}")





