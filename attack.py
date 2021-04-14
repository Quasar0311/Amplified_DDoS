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

data = ('32 ff 00')
data_list = data.split(" ")
data_s = ''.join(data_list).encode("utf-8").hex()

ip = IP(src = source_ip, dst = target_ip)
udp = UDP(sport = 68, dport = target_port)
payload = Raw(load = '\x00\x00\x00\x00\x00\x01\x00xxxxttts\r\n')
payload_h = Raw(load = data_s)
payload_s = "helll"
dns = DNS(rd = 1, qd = DNSQR(qname = "qq.com"))
packet = ip/udp/dns
#print(packet[IP].show2())
#print(packet[UDP].show2())
#print("pack!")
#print(packet.show2())
for i in range(10):
	send(packet)
#ans, unans = sr(packet)
#print(ans.summary())

ip2 = IP(dst = target_ip)
udp2 = UDP(sport = 22, dport = target_port_ntp)
payload2 = Raw(load = (b'\x1b' + b'\0'*47))
#data2 = b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #+ 39 * b'\0'
payload2_normal = Raw(load = b'\x1b' + b'\0'*47)
packet2 = ip2 / udp2 / payload2_normal
#print(packet2.show2())
#ans, unans = sr(packet2)
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

#tcp_pkt = IP(src = source_ip, dst = target_ip) / TCP(sport = 68, dport = 80, flags = 'S')
#answer = sr1(tcp_pkt)
#print(answer[TCP].ack)
#for i in range(10):
#	send(tcp_pkt)
#answer = sr1(IP(dst="192.168.20.1")/UDP(dport = 53)/DNS(rd=1, qd=DNSQR(qname="www.google.com")), verbose=0)
#print(answer[DNS].summary())

pkt = IP(src = "192.168.10.1", dst = "192.168.20.1") /fuzz(UDP(sport = 68, dport = 123)/NTP(leap = 0, version = 2, mode = 3, stratum = 3, poll = 0, precision = 0))



data = '\xd7\x3d\x03\x2a\x00\x06\x00\x48'

pkt2 = IP(src = "192.168.10.1", dst = "192.168.20.1") / UDP(sport = 68, dport = 123) / data
#ans2 = sr1(pkt2)
#print(ans2)
print(pkt.show2())
print(len(pkt))
ans = sr1(pkt)
print(ans)
print(len(ans))
#for i in range(10):
#	send(pkt)
