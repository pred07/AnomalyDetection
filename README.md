# NetShield: Network Anomaly & Attack Discovery

NetShield is a powerful, rule-based Network Packet Analysis tool built with Python and Streamlit. It allows security analysts to upload PCAP files and instantly detect anomalies, scanning behaviors, and common network attacks through statistical analysis and signature matching.

## 🚀 Quick Start for Beginners

### 1. Prerequisites
Ensure you have Python 3.10 or higher installed. You will also need `Npcap` (Windows) or `libpcap` (Linux/macOS) for packet handling.
- **Windows**: Download and install [Npcap](https://npcap.com/#download).
- **Linux**: `sudo apt-get install tcpdump libpcap-dev`

### 2. Clone the Repository
```bash
git clone https://github.com/pred07/AnomalyDetection.git
cd AnomalyDetection
```

### 3. Setup Environment
It is recommended to use a virtual environment:
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run the Application
```bash
streamlit run app.py
```

### 6. Analyze Traffic
1. Open the URL provided (usually `http://localhost:8501`).
2. Drag and drop a `.pcap` or `.pcapng` file into the upload area.
3. View the **Traffic Overview**, **Alerts**, and **Threat Scoreboard**.
4. Download the **PDF Report** for your documentation.

## 🛠️ Tech Stack
- **Python**: Core logic.
- **Streamlit**: Web Interface.
- **Scapy**: Packet Parsing.
- **Pandas/NumPy**: Feature Engineering & Statistics.
- **Plotly**: Visualizations.
- **FPDF**: PDF Generation.

## 📂 Project Structure
Refer to `DOCUMENTATION.md` for a detailed breakdown of the architecture and modules.

## ⚖️ License
MIT License
