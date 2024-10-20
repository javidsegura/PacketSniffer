# Hexadecimal string
hex_string = "77 61 73 73 75 70 20 6e 69 67 67 61"

# Split the hex string into individual hex values
hex_values = hex_string.split()

# Convert each hex value to a character and join them to form the final string
result = ''.join(chr(int(h, 16)) for h in hex_values)

print(result)
