from scapy.all import *
import time
import random

# הגדרת יעד פיקטיבי חיצוני כדי לוודא שהתעבורה עוברת בכרטיס הרשת
target_ip = "1.2.3.4"

print(f"[Attacker] Targeting external IP: {target_ip}")
print("1. Simulate SYN Scan")
print("2. Simulate XMAS Scan")
print("3. Simulate NULL Scan")
print("4. Simulate ARP Scan")

choice = input("Choose attack type (1-4): ")

if choice == "1":
    print("[*] Launching SYN Scan...")
    for port in range(20, 45):
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
        time.sleep(0.01)

elif choice == "2":
    print("[*] Launching XMAS Scan...")
    send(IP(dst=target_ip)/TCP(dport=80, flags="FPU"), verbose=0)

elif choice == "3":
    print("[*] Launching NULL Scan...")
    send(IP(dst=target_ip)/TCP(dport=80, flags=""), verbose=0)

elif choice == "4":
    print("[*] Launching ARP Scan...")
    target_prefix = target_ip.rsplit('.', 1)[0]
    for i in range(1, 20):
        fake_target = f"{target_prefix}.{random.randint(100,200)}"
        send(ARP(op=1, pdst=fake_target), verbose=0)
        time.sleep(0.01)

print("[V] Attack packet(s) sent.")
