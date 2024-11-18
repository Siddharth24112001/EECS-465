from scapy.all import *
import re

# Craft a valid DNS packet to query for scanme.nmap.org
# Help with crafting DNS packets in Scapy -> https://thepacketgeek.com/scapy-p-09-scapy-and-dns/

dns_ip = "8.8.8.8"
dns_req = IP(dst=dns_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="scanme.nmap.org"))


answer = sr1(dns_req, verbose=0)
print(answer[DNS].summary())

target_IP = answer[DNS].an.rdata
print("IP address for scanme.nmap.org:", target_IP)

# Craft a valid ICMP packet to the IP address of scanme.nmap.org 
# Help with crafting ICMP packets in Scapy -> https://dev.to/ankitdobhal/let-s-ping-the-network-with-python-scapy-5g18

icmp = IP(dst=target_IP)/ICMP()


resp = icmp.summary()

if resp == None:
    print("This is an empty packet")

else:
    # Create a TCP request to scanme.nmap.org 
    # Print response
    # Tutorial on creating a Scapy port scanner (can be adapted to send one packet to a single port):  
    # https://medium.com/@iphelix/scapy-599bbd0b5e9e

    print ("This is my ICMP packet:", resp)
    
    http_req = IP(dst=target_IP)/TCP(dport=80)


    http_resp = sr1(http_req, verbose=0)
    print(http_resp.summary())
