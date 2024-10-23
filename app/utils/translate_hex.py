""" Translated the payload of the packet (in bytes) to a readable string (in Unicode)"""

import pandas as pd

def hex_to_string(record_id:int) -> str | int:
    try:
        df = pd.read_csv(".././utils/PacketsResultsCSV.csv")
        hex_values = df.loc[df["packet_id"] == record_id, "payload"].values[0].split()

        # Convert each hex value to a character and join them to form the final string
        result = ''.join(chr(int(h, 16)) for h in hex_values)

        return result
    except Exception as e:
        return -1

