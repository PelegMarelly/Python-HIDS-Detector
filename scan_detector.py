from scapy.all import *
from collections import defaultdict
import tkinter as tk
from tkinter import messagebox
import threading


print("[System] Monitoring network traffic for anomalies.")

syn_scanners = defaultdict(set)
arp_scanners = defaultdict(set)
reported_threats = set()

def show_alert(title, message):
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        messagebox.showwarning(title=title, message=message)
        root.destroy()
    except:
        pass

def analyze_packet(packet):
    try:
        if packet.haslayer(ARP) and packet[ARP].op == 1:
            src_ip = packet[ARP].psrc
            target_ip = packet[ARP].pdst
            
            arp_scanners[src_ip].add(target_ip)
            
            if len(arp_scanners[src_ip]) > 10:
                threat_id = f"{src_ip}_ARP"
                if threat_id not in reported_threats:
                    print(f"[Alert] ARP scanning activity detected. Source: {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert, args=("Network Security Alert", f"ARP scanning activity detected.\nSource: {src_ip}")).start()

        elif packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            if flags == 0 or str(flags) == "":
                threat_id = f"{src_ip}_NULL"
                if threat_id not in reported_threats:
                    print(f"[Alert] Malformed packet detected (NULL Scan). Source: {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert, args=("Security Alert", f"NULL Scan detected.\nSource: {src_ip}")).start()

            elif 'F' in str(flags) and 'P' in str(flags) and 'U' in str(flags):
                threat_id = f"{src_ip}_XMAS"
                if threat_id not in reported_threats:
                    print(f"[Alert] Malformed packet detected (XMAS Scan). Source: {src_ip}")
                    reported_threats.add(threat_id)
                    threading.Thread(target=show_alert, args=("Security Alert", f"XMAS Scan detected.\nSource: {src_ip}")).start()

            elif flags == 'S':
                syn_scanners[src_ip].add(dst_port)
                if len(syn_scanners[src_ip]) > 15:
                    threat_id = f"{src_ip}_SYN"
                    if threat_id not in reported_threats:
                        print(f"[Alert] Port scanning activity detected. Source: {src_ip}")
                        reported_threats.add(threat_id)
                        threading.Thread(target=show_alert, args=("Network Security Alert", f"Port scanning activity detected.\nSource: {src_ip}")).start()

    except Exception:
        pass

sniff(prn=analyze_packet, store=0)
