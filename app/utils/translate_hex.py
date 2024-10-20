def hex_to_string(hex_string):
      try:
          hex_values = hex_string.split()

          # Convert each hex value to a character and join them to form the final string
          result = ''.join(chr(int(h, 16)) for h in hex_values)

          return result
      except:
           return "Invalid hexadecimal input"
      