""" Finds the sent packet in the CSV file """
import pandas as pd

def filter_packets(src_ip:str = "10.192.67.245", dest_port:int = 80):
    try:
        df = pd.read_csv("/Users/javierdominguezsegura/Programming/College/Sophomore/Cprogramming/PacketSniffer/utils/PacketsResultsCSV.csv")

        df = df[(df["src_ip"] == src_ip) & (df["src_ip"] == df["dest_ip"]) & (df["dest_port"] == dest_port) & (df["payload"].isna() == False)]
        return df #.reset_index(drop=True, inplace=True)
    except Exception as e:
        return (f"Error filtering packets: {e}")



