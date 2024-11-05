from scapy.all import IP, ICMP, send


def sendicmp():
    destip = '172.18.0.2'

    packet =  IP(dst=destip, ttl=1) /  ICMP()
    send(packet)

if __name__ == "__main__":
    sendicmp()
