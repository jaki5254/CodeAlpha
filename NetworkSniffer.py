import scapy.all as scapy
from scapy.layers import http

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_tcp(packet):
    src_port = packet[scapy.TCP].sport
    dst_port = packet[scapy.TCP].dport
    print(f"TCP Source Port: {src_port} | TCP Destination Port: {dst_port}")

def process_udp(packet):
    src_port = packet[scapy.UDP].sport
    dst_port = packet[scapy.UDP].dport
    print(f"UDP Source Port: {src_port} | UDP Destination Port: {dst_port}")

def process_icmp(packet):
    icmp_type = packet[scapy.ICMP].type
    icmp_code = packet[scapy.ICMP].code
    print(f"ICMP Type: {icmp_type} | ICMP Code: {icmp_code}")

def process_http(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)
        
def process_ssl(packet):
    ssl_data = packet[scapy.Raw].load
    print(f"SSL/TLS Data: {ssl_data}")

def process_dns(packet):
    dns_query = packet[scapy.DNS].qd.qname.decode()
    print(f"DNS Query: {dns_query}")

def process_arp(packet):
    arp_src = packet[scapy.ARP].psrc
    arp_dst = packet[scapy.ARP].pdst
    print(f"ARP Source IP: {arp_src} | ARP Destination IP: {arp_dst}")

def process_ipv6(packet):
    ipv6_src = packet[scapy.IPv6].src
    ipv6_dst = packet[scapy.IPv6].dst
    print(f"IPv6 Source: {ipv6_src} | IPv6 Destination: {ipv6_dst}")

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        ttl = packet[scapy.IP].ttl
        id = packet[scapy.IP].id
        flags = packet[scapy.IP].flags
        print(f"IP Source: {ip_src} | IP Destination: {ip_dst} | Protocol: {protocol}")
        print(f"TTL: {ttl} | ID: {id} | Flags: {flags}")
        process_functions = {
            scapy.TCP: process_tcp,
            scapy.UDP: process_udp,
            scapy.ICMP: process_icmp,
            http.HTTPRequest: process_http,
            scapy.DNS: process_dns,
            scapy.ARP: process_arp,
            scapy.IPv6: process_ipv6
        }

        for layer in process_functions:
            if packet.haslayer(layer):
                 print(packet)
              
#if use wireless communication than not use eth0, use wlan0
sniff_packets("eth0")
