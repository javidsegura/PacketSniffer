INTERFACES = {
    "en0": "Wi-Fi",
    "en1": "Ethernet",
    "en2": "Bluetooth",
    "en3": "Thunderbolt 1",
    "en4": "Thunderbolt 2",
    "en5": "Thunderbolt 3",
    "en6": "Thunderbolt 4",
    "en7": "USB Ethernet",
    "en8": "Virtual Ethernet (VM Network)",
    "en9": "AirPort (Wireless Adapter)",
    "en10": "5G Cellular",
    "en11": "4G LTE Cellular",
    "en12": "Satellite Adapter",
    "en13": "Fiber Optic Connection",
    "en14": "Mobile Hotspot",
    "en15": "VPN Adapter",
    "en16": "Loopback Interface",
    "en17": "USB Tethering",
    "en18": "Dock Ethernet",
    "en19": "USB Wi-Fi Adapter",
    "en20": "Powerline Adapter",
    "en21": "ISDN Adapter",
    "en22": "FireWire Ethernet",
    "en23": "Infrared Adapter",
    "en24": "Coaxial Broadband",
    "en25": "Zigbee Adapter",
    "en26": "LoRaWAN Adapter",
    "en27": "WiGig Adapter (802.11ad)",
    "en28": "Millimeter Wave Adapter",
    "en29": "Dual-Band Wi-Fi Adapter",
    "en30": "Tri-Band Wi-Fi Adapter",
    "en31": "Mesh Network Node",
    "en32": "Ethernet over HDMI",
    "en33": "Ethernet over USB-C",
    "en34": "PCIe Ethernet Card",
    "en35": "External Thunderbolt Ethernet",
    "en36": "Satellite Internet Modem",
    "en37": "GPON Fiber Interface",
    "en38": "DSL Modem Interface",
    "en39": "Legacy Dial-up Modem",
    "en40": "Ham Radio Modem",
    "lo0": "Local Loopback",
    "bridge0": "Bridge Interface",
    "utun0": "VPN Tunnel (Userland)",
    "utun1": "VPN Tunnel (Additional)",
    "ap": "Access Point Mode",
    "tap0": "Virtual Network Interface (TAP)",
    "tun0": "Virtual Network Interface (TUN)",
    "fw0": "FireWire Interface",
    "ppp0": "Point-to-Point Protocol Interface",
    "stf0": "IPv6 to IPv4 Tunnel",
    "p2p0": "Peer-to-Peer Wi-Fi",
    "awdl0": "Apple Wireless Direct Link",
    "vboxnet0": "VirtualBox Host-Only Network",
    "docker0": "Docker Bridge Network",
    "vmnet1": "VMware Host-Only Network",
    "vmnet8": "VMware NAT Network",
}

def get_friendly_interface_name(interface):
    return INTERFACES.get(interface, interface)