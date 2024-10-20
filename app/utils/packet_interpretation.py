import pandas as pd

def filter_packets(src_ip:str = "10.192.67.245", dest_port:int = 80):
    df = pd.read_csv("../utils/PacketsResultsCSV.csv")
    # Read only those that have src_ip = 10.192.67.245
    df = df[(df["src_ip"] == src_ip) & (df["src_ip"] == df["dest_ip"]) & (df["dest_port"] == dest_port) & (df["payload"].isna() == False)]
    return df.reset_index(drop=True, inplace=True)