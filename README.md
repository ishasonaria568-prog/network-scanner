# Network Scanner — Built by Isha Sonaria

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-slate.svg)](LICENSE)
[![Platform: Linux / Kali / Vercel](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Vercel-slate.svg)]()

> A clean, trustworthy, defensive network discovery and security inventory platform. Features an educational **modern light-themed Web GUI deployable on Vercel**, a **standalone Python CLI** for Kali Linux terminals, and an **authenticated External Scanner Agent**.

* **Author:** Isha Sonaria
* **GitHub:** [https://github.com/ishasonaria568-prog](https://github.com/ishasonaria568-prog)
* **Cybersecurity Portfolio:** [https://isha-sonaria-cybersecurity-portfoli.vercel.app/](https://isha-sonaria-cybersecurity-portfoli.vercel.app/)

---

## Architecture Overview: Split-Plane Engine

Traditional network discovery tools face fundamental architectural barriers when migrating to serverless cloud environments (such as Vercel or AWS Lambda):
* **Layer 2 ARP (Address Resolution Protocol)** operates exclusively on a local Ethernet broadcast domain (`FF:FF:FF:FF:FF:FF`). Cloud serverless containers run in multi-tenant network namespaces without raw socket permissions (`CAP_NET_RAW`) or physical LAN connectivity.
* Rather than fabricating fake devices or claiming unsupported capabilities, **Network Scanner** implements an enterprise **split-plane architecture**:

```
+-----------------------------------------------------------------------------------+
|                           CONTROL PLANE (Vercel / Cloud)                          |
|  - Clean Light UI (Soft Slate-50 Canvas, White Cards, Crisp Blue Accents)         |
|  - Embedded Scan Configuration Panel & CIDR Educational Explainer                 |
|  - Input Validation & Subnet Range Sanitization (SSRF Protection)                 |
|  - Scan Orchestration & Job Queueing                                              |
|  - Real-time Capability Reporting (arp_discovery: false on Vercel)                |
|  - Native Layer 3 TCP Connect Scanner (for permitted targets)                    |
|  - Searchable, Sortable Results Table with CSV & JSON Exporters                   |
+-----------------------------------------+-----------------------------------------+
                                          |
                      HTTPS Poll & Bearer Token Auth
                                          |
+-----------------------------------------v-----------------------------------------+
|                       EXECUTION PLANE (Local Kali Linux Agent)                    |
|  - Runs as a standalone Python process inside target physical LAN                 |
|  - Real Layer 2 ARP Broadcasts using Scapy (`Ether() / ARP()`)                    |
|  - Hardware MAC extraction & OUI Vendor database resolution                       |
|  - Multithreaded Reverse DNS Hostname Resolution                                  |
|  - Defense-in-depth target allowlist verification                                 |
|  - Secure result submission back to the web console                               |
+-----------------------------------------------------------------------------------+
```

---

## How Network Scanning Works

The application includes a dedicated **How It Works** section explaining the 6-step discovery sequence:

```
[User Input] ➔ [Validation] ➔ [Scan Engine] ➔ [Result Processing] ➔ [Results Table] ➔ [Export]
```

1. **Step 1 — Enter a network:** The user inputs an IPv4 address or CIDR subnet (such as `192.168.1.0/24` or `127.0.0.1/32`).
2. **Step 2 — Validate the target:** The application validates address syntax, checks prefix sizes (enforcing maximum safe limits), prohibits cloud metadata addresses, and detects available engine capabilities.
3. **Step 3 — Discover devices:** On supported local networks, the Python scanner broadcasts ARP requests. For cloud or remote networks, it runs non-blocking TCP connect probes against selected ports.
4. **Step 4 — Collect device information:** Actual responses are captured: ARP yields IP and physical MAC addresses; reverse DNS attempts to resolve hostnames; TCP connection probes record port availability and service banners.
5. **Step 5 — Process results:** A thread-safe bounded pool aggregates results, records round-trip latency, applies evidence-backed OS rules, and logs errors.
6. **Step 6 — Display and export:** The clean web dashboard renders the inventory in a searchable, sortable table and exports to CSV and JSON formats.

### Important Limitations
* **ARP requires local network access:** ARP broadcast frames (`who-has`) do not route across Internet gateways.
* **MAC addresses are not obtainable across the Internet:** Only Layer 2 switches/segments provide physical MACs.
* **Reverse DNS does not always return a hostname:** PTR records must be configured by network administrators.
* **Unresponsive does not mean offline:** Host-based firewalls (Windows Defender, iptables) frequently drop unsolicited probes.
* **TCP port scanning is distinct from ARP discovery:** TCP connect checks application service availability, while ARP discovers physical link connectivity.

---

## 1. Web Dashboard Guide

The web dashboard is organized into 5 clean, intuitive sections:

1. **Scanner:** Primary configuration panel with CIDR notation guide, quick preset buttons, scan method selection, port profiles, collapsible advanced settings, and mandatory authorization confirmation.
2. **Results:** Searchable, sortable table of discovered devices with IP, MAC, hostname, open ports, evidence-backed OS classification, latency, and CSV/JSON export actions.
3. **How It Works:** Educational visual flow diagram, 6 numbered steps, and technical network limitations.
4. **CLI Guide:** Beginner-friendly instructions for both the web GUI and the standalone terminal CLI.
5. **Settings & Connection:** Agent token pairing, live heartbeat status, copyable agent command, and collapsible technical architecture matrix.

---

## 2. CLI Mode — Kali Linux and Linux Terminals

The CLI operates completely independently of Node.js and requires only Python 3.9+.

### Installation

```bash
# Clone the repository
git clone https://github.com/ishasonaria568-prog/network-scanner.git
cd network-scanner

# Create and activate a clean virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### CLI Command Reference

```bash
# Inspect platform capabilities & Scapy permissions:
python -m network_scanner capabilities

# Layer 2 ARP discovery on local subnet (requires sudo on Linux):
sudo python -m network_scanner scan --network 192.168.1.0/24

# ARP discovery with 50 worker threads and common TCP port probing:
sudo python -m network_scanner scan --network 192.168.1.0/24 --threads 50 --ports 22,80,443,445

# Unprivileged Layer 3 TCP discovery (when sudo is unavailable):
python -m network_scanner scan --network 192.168.1.0/24 --method tcp --ports 80,443,22

# Export results directly to CSV or JSON:
sudo python -m network_scanner scan --network 192.168.1.0/24 --format csv --output results.csv
sudo python -m network_scanner scan --network 192.168.1.0/24 --format json --output results.json

# Display help:
python -m network_scanner --help
```

---

## 3. External Scanner Agent

To enable Layer 2 ARP discovery from the Vercel web GUI:

1. Navigate to the **Settings & Connection** tab to view your **Agent Pairing Token**.
2. Run the agent on your authorized Kali Linux machine:

```bash
sudo python3 -m agent.client \
  --server-url https://your-scanner-app.vercel.app \
  --token <YOUR_AGENT_TOKEN> \
  --name "Kali-Primary-Node"
```

The agent polls for queued scan jobs, verifies the target is within its configured `--allow-subnet` list, runs real Scapy ARP broadcasts, and posts results back securely.

---

## 4. Automated Testing

Run the Python unit test suite:

```bash
python3 -m unittest discover tests -v
```

14/14 automated tests verify:
* IPv4 and CIDR subnet calculation
* Boundary enforcement and rejection of oversized networks
* Host enumeration excluding network/broadcast addresses
* MAC vendor OUI prefix resolution
* Thread-safe result aggregation
* CSV and JSON report serialization
* Conservative OS fingerprint evidence matching
* Agent security boundary allowlist enforcement

---

## 5. Branding & Portfolio Links

* **Project:** Network Scanner
* **Author:** **Isha Sonaria**
* **GitHub:** [https://github.com/ishasonaria568-prog](https://github.com/ishasonaria568-prog)
* **Portfolio:** [https://isha-sonaria-cybersecurity-portfoli.vercel.app/](https://isha-sonaria-cybersecurity-portfoli.vercel.app/)
