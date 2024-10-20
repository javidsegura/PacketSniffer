import pandas as pd

def hex_to_string(record_id:int):
            df = pd.read_csv("/Users/javierdominguezsegura/Programming/College/Sophomore/Cprogramming/PacketSniffer/utils/PacketsResultsCSV.csv")
            hex_values = df.loc[df["packet_id"] == record_id, "payload"].values[0].split()

            # Convert each hex value to a character and join them to form the final string
            result = ''.join(chr(int(h, 16)) for h in hex_values)

            return result

