from scapy.all import IP, ICMP, sniff

# Implement your ICMP receiver here



def handlepacket(packet):
    if packet.haslayer( ICMP) and packet[ IP].ttl == 1 and packet[ ICMP].type == 8:  # Type 8 is an ICMP request
        packet.show()

def captureicmp():
    sniff(filter="icmp", prn=handlepacket)

if __name__ == "__main__":
    captureicmp()
