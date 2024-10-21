PORT_CATEGORIES = {}

def create_port_categories():
    """
    Creates a dictionary of port categories.
    """
    global PORT_CATEGORIES
    PORT_CATEGORIES = {
    # Well-known ports (0-1023)
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    443: "HTTPS",
    465: "SMTPS",
    514: "Syslog",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    990: "FTPS",
    1234: "Qtel",
    5000: "UPnP",
    5222: "XMPP",
    5223: "XMPP",
    5900: "VNC",
    5984: "CouchDB",
    6000: "X11",
    6379: "Redis",
    6666: "Doom",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB",
    3306: "MySQL",
    1433: "MSSQL",
    1521: "Oracle",
    3389: "RDP",
    50000: "SAP",
    49152: "Dynamic/Private",
    # ... add more well-known and registered ports as needed
}


    # Add ranges for dynamic/private ports
    for port in range(49152, 65536):
        PORT_CATEGORIES[port] = "Dynamic/Private"

    return PORT_CATEGORIES

def get_port_category(port):
    """
    Retrieves the category for a given port.
    
    :param port: The port number to look up
    :param categories: The dictionary of port categories
    :return: The category of the port, or "Unknown" if not found
    """
    global PORT_CATEGORIES
    if port in PORT_CATEGORIES:
        return PORT_CATEGORIES[port]
    elif 0 <= port <= 1023:
        return "Well-known"
    elif 1024 <= port <= 49151:
        return "Registered"
    elif 49152 <= port <= 65535:
        return "Dynamic/Private"
    else:
        return "Unknown"
    

create_port_categories()
print(get_port_category(80))
