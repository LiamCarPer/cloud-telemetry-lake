import scapy.all as scapy
from datetime import datetime
import os
import time

LOG_FILE = "/detection/logs/iptables.log"

def get_interface(ip):
    # Map destination IP to output interface
    if ip.startswith("172.21.0."):
        return "eth1"
    elif ip.startswith("172.22.0."):
        return "eth0"
    elif ip.startswith("172.23.0."):
        return "eth3"
    elif ip.startswith("172.24.0."):
        return "eth2"
    return "unknown"

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Check if traffic is from IT zone (Attacker 172.24.0.10) to internal zones, which is blocked
        if src_ip == "172.24.0.10" and (dst_ip.startswith("172.21.0.") or dst_ip.startswith("172.22.0.") or dst_ip.startswith("172.23.0.")):
            t = datetime.now()
            time_str = t.strftime("%b %d %H:%M:%S")
            in_iface = "eth2"
            out_iface = get_interface(dst_ip)
            
            proto = "TCP"
            spt_dpt = ""
            if packet.haslayer(scapy.TCP):
                proto = "TCP"
                spt_dpt = f"SPT={packet[scapy.TCP].sport} DPT={packet[scapy.TCP].dport}"
            elif packet.haslayer(scapy.UDP):
                proto = "UDP"
                spt_dpt = f"SPT={packet[scapy.UDP].sport} DPT={packet[scapy.UDP].dport}"
            elif packet.haslayer(scapy.ICMP):
                proto = "ICMP"
                
            length = len(packet)
            ttl = packet[scapy.IP].ttl
            packet_id = packet[scapy.IP].id
            tos = f"0x{packet[scapy.IP].tos:02x}"
            
            uptime = time.clock_gettime(time.CLOCK_MONOTONIC)
            
            log_line = f"{time_str} ot-gateway kernel: [{uptime:.6f}] [IPTABLES_DROP] IN={in_iface} OUT={out_iface} SRC={src_ip} DST={dst_ip} LEN={length} TOS={tos} PREC=0x00 TTL={ttl} ID={packet_id} PROTO={proto} {spt_dpt}\n"
            
            with open(LOG_FILE, "a") as f:
                f.write(log_line)
            print(f"[IPTABLES_MOCK] Logged drop: {src_ip} -> {dst_ip}")

print("Starting Mock IPTABLES Dropped Packet Sniffer...")
scapy.sniff(iface="eth2", filter="ip", prn=process_packet, store=0)
