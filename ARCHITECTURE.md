# Deep Packet Inspection (DPI) Engine v2.0

## 🌟 Overview
This project is an advanced, high-performance **Deep Packet Inspection (DPI) Engine** built in C++ that has been modernized to include a **Real-Time Full-Stack Web Dashboard**. The system captures network traffic (either via PCAP files or live interfaces), analyzes packets up to Layer 7 (Application Layer), tracks connections, extracts Server Name Indications (SNI), and dynamically blocks traffic based on user-defined rules. 

The newest v2.0 update introduces a completely revamped direct-dispatch threading model, advanced protocol parsing (IPv6 & VLAN), and a stunning React-based UI that visualizes network traffic in real time.

---

## 🏗️ System Architecture

The project is split into three main components:

### 1. The C++ DPI Daemon (The Core Engine)
Written in highly optimized C++17, this is the brain of the operation.
- **Packet Ingestion**: Uses `libpcap` to read from offline `.pcap` files or capture live traffic directly from network interfaces (e.g., `en0`, `eth0`).
- **Deep Parsing**: Extracts Ethernet, VLAN (802.1Q), IPv4, IPv6, TCP, and UDP headers. It reassembles streams sufficiently to extract Layer 7 TLS Client Hello messages to find the **SNI (Server Name Indication)**.
- **Direct Dispatch Threading Model**: Packets are hashed based on their 5-tuple (Source IP, Dest IP, Source Port, Dest Port, Protocol) and routed directly to a specific `FastPath` worker thread. This eliminates lock contention and load-balancer starvation.
- **Application Classification**: Maps SNIs to known applications (e.g., `googlevideo.com` → YouTube, `cdninstagram.com` → Instagram) using a highly specific rule engine.
- **IPC & Control Socket**: The engine spins up two lightweight UDP sockets:
  - **Port 5005 (Control)**: Listens for incoming commands (e.g., `BLOCK_IP 192.168.1.50`).
  - **Port 5006 (Stats)**: Broadcasts JSON-serialized network metrics (PPS, active connections, drops) every second.

### 2. Node.js WebSocket Bridge (The Middleman)
A lightweight Node.js server located in `dashboard/backend/`.
- **UDP Listener**: Binds to UDP port 5006 to receive the high-frequency JSON telemetry from the C++ Daemon.
- **WebSocket Broadcaster**: Forwards the telemetry instantly to all connected browser clients via WebSockets (`ws://localhost:3001`).
- **REST API**: Exposes endpoints (`/api/rules/block`) that the frontend can call. The Node server translates these HTTP POST requests into UDP datagram commands and fires them to the C++ engine on port 5005.

### 3. React + Vite Dashboard (The Frontend)
A state-of-the-art, premium dark-themed web application located in `dashboard/frontend/`.
- **Live Throughput Chart**: A dynamically updating bar chart plotting Packets Per Second (PPS) over a rolling 60-second window.
- **Application Distribution**: Animated progress bars showing the exact protocol and app distribution of current bandwidth.
- **Rule Controller**: An interactive control panel where users can ban IPs, Domains, or Applications with a single click.
- **Alert Console**: A real-time scrolling feed of security events and dropped packets.

---

## 🚀 How to Run the Project

### Prerequisites
- `cmake` and a C++17 compiler (GCC/Clang)
- `Node.js` (v16+) and `npm`
- `libpcap` (pre-installed on macOS, `apt install libpcap-dev` on Linux)

### Step 1: Compile the C++ Engine
```bash
cd Packet_analyzer
cmake -B build -S .
cmake --build build
```

### Step 2: Start the Web Backend
```bash
cd dashboard/backend
npm install
npm start
```
*(Runs on port 3001)*

### Step 3: Start the Web Frontend
```bash
cd dashboard/frontend
npm install
npm run dev
```
*(Runs on http://localhost:5173)*

### Step 4: Launch the DPI Engine
**For testing with a PCAP file:**
```bash
./build/dpi_daemon file test_dpi.pcap output.pcap --control --stats
```

**For Live Network Capture (requires sudo):**
```bash
sudo ./build/dpi_daemon live en0 --control --stats
```
*(Replace `en0` with your active network interface. Use `./build/dpi_daemon list-interfaces` to see available interfaces).*

Once the engine is running, open your browser to `http://localhost:5173`. You will see the dashboard light up with real-time network traffic analysis!

---

## 🛠️ Tech Stack
- **Core**: C++17, libpcap
- **Backend Bridge**: Node.js, Express, `ws` (WebSockets), `dgram` (UDP)
- **Frontend Dashboard**: React 19, Vite, Vanilla CSS (Glassmorphism UI)
