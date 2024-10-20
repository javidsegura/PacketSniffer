import pandas as pd


def filter_packets(src_ip:str = "10.192.67.245"):
    df = pd.read_csv("../utils/PacketsResultsCSV.csv")
    # Read only those that have src_ip = 10.192.67.245
    #df = df[(df["src_ip"] == src_ip) & (df["src_ip"] == df["dest_ip"])]
    return df  
