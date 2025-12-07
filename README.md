# Multi-Layer Host-Based IDS (HIDS)

A Python-based Intrusion Detection System designed to monitor network traffic in real-time and detect anomalous behavior indicative of a compromised host.

The system analyzes traffic at **Layer 2 (Data Link)** and **Layer 4 (Transport)** to identify various reconnaissance techniques used by malware and threat actors during the post-exploitation phase (e.g., Lateral Movement).

## Key Features

* **Real-Time Sniffing:** Uses `Scapy` to capture and analyze packets on the fly.
* **SYN Scan Detection:** Identifies rapid TCP connection attempts to multiple ports.
* **ARP Scan Detection:** Detects local network discovery attempts (Layer 2 reconnaissance).
* **Stealth Scan Detection:** Identifies malformed packets used to bypass firewalls:
    * **NULL Scans** (No flags set).
    * **XMAS Scans** (FIN, PSH, URG flags set).
* **GUI Alert System:** Provides immediate visual feedback upon threat detection.

## Getting Started

### Prerequisites

* **Python 3.x** installed on the host machine.
* **Scapy** library. Install via pip:
    ```bash
    pip install scapy
    ```
* **Windows Users:** **Npcap** must be installed to allow packet capturing. Ensure the option *"Install Npcap in WinPcap API-compatible Mode"* is selected during installation.

### Installation

1.  Clone the repository to your local machine.
2.  Navigate to the project directory.

## Usage Instructions

To demonstrate the system's capabilities, you will need two separate terminal instances: one to run the defense mechanism (IDS) and one to simulate the attack.

### 1. Deploy the Detector (The Defense)

The detection script requires access to the network interface, which mandates administrative privileges.

1.  Open a terminal or command prompt as **Administrator** (or use `sudo` on Linux).
2.  Execute the detector script:
    ```bash
    sudo python3 scan_detector.py
    ```
3.  The system will initialize and begin monitoring network traffic.

### 2. Simulate Attacks (The Offense)

The repository includes an `attacker.py` script designed to simulate a compromised host performing reconnaissance.

1.  Open a **separate** terminal window.
2.  Edit `attacker.py` and ensure the `target_ip` variable is set to an **external IP address** (e.g., another device on your network like `192.168.1.50` or a public IP).
    > **Technical Note:** We use an external IP to force traffic through the physical Network Interface Card (NIC), allowing the sniffer to capture outbound packets. Using `localhost` might cause the OS to route traffic via the Loopback interface, bypassing the sniffer.
3.  Run the attack simulation:
    ```bash
    sudo python3 attacker.py
    ```
4.  **Select an Attack Vector:** The script will present a menu. Choose an option (1-4) to simulate different scan types (SYN, XMAS, NULL, or ARP).

### Expected Behavior

Upon executing an attack, the IDS will detect the pattern:

* **Console Output:** The detector terminal will log the threat type, source IP, and specific details (e.g., "XMAS Scan detected").
* **GUI Alert:** A pop-up warning window will appear on the screen, notifying the user of the malicious activity.
