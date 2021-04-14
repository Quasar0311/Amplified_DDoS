from scapy.all import *
import time
import sys
import socket
import struct
from time import ctime
import random

source_ip = "192.168.30.1"
target_ip = "192.168.20.1"
source_port = 68
target_port = 53
target_port_ntp = 123
TIME1970 = 2208988800

ip = IP(src = source_ip, dst = target_ip)
udp = UDP(sport = 68, dport = target_port)
dns = DNS(rd = 1, qd = DNSQR(qname = "a.com"))
packet = ip/udp/dns
#print(packet[IP].show2())
#print(packet[UDP].show2())
#print("pack!")
#print(packet.show2())
for i in range(20):
	send(packet)
#ans, unans = sr(packet)
#print(ans.summary())

def sntp_client():
	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = b'www.google.com' + b'\0'*33
	print(data)
	client.sendto(data, (target_ip, target_port))
	data, address = client.recvfrom(1024)
	if data:
		print('Response received from:', address)
		print(data)
	t = struct.unpack( '!12I', data )[10]
	t -= TIME1970	
	print (time.ctime(t))

#sntp_client()

pkt = IP(src = "192.168.30.1", dst = "192.168.20.1") /fuzz(UDP(sport = 68, dport = 123)/NTP(leap = 0, version = 2, mode = 3, stratum = 3, poll = 0, precision = 0))

data = '\xd7\x3d\x03\x2a\x00\x06\x00\x48'
pkt2 = IP(src = "192.168.10.1", dst = "192.168.20.1") / UDP(sport = 68, dport = 123) / data
#ans2 = sr1(pkt2)
#print(ans2)
#print(pkt.show2())
print(len(pkt))
#ans = sr1(pkt)
#print(ans)
#print(len(ans))
for i in range(20):
	send(pkt)
