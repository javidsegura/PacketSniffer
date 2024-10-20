import pandas as pd


df = pd.read_csv("utils/PacketsResultsCSV.csv")

# Read only those that have src_ip = 10.192.67.245
df = df[(df["src_ip"] == "10.192.67.245") & (df["src_ip"] == df["dest_ip"])]

print(df)
