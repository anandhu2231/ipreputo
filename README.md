# IPREPUTO - IP Reputation Analyzer

IPREPUTO is an advanced command-line tool designed to analyze the reputation of IP addresses using multiple threat intelligence sources, including **VirusTotal, AlienVault, PulseDive, and AbuseIPDB**. It provides valuable insights into potential threats, helping security analysts, SOC teams, and researchers identify **malicious** IPs efficiently.

## 🚀 Features

- **Multi-Source Reputation Check** – Fetches IP reputation from **VirusTotal, AlienVault, PulseDive, and AbuseIPDB**.
- **ISP & Location Info** – Retrieves ISP details and geographical data.
- **Risk Categorization** – Classifies IPs as **Malicious** or **Non-Malicious**.
- **Interactive CLI** – Displays a real-time loading animation during execution.
- **Persistent API Keys** – Stores API keys securely for long-term use.
- **Supports CSV & Excel** – Processes bulk IPs from `.csv` or `.xlsx` files.

## 🛠 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/ipreputo.git
cd ipreputo
```

### 2️⃣ Install Dependencies
```bash
pip install .
```

## 🔑 Setup API Keys
The first time you run the tool, it will prompt you to enter API keys for **VirusTotal, AlienVault, PulseDive, and AbuseIPDB**. These keys will be stored securely for future use.

## ⚡ Usage
```bash
ipreputo -i input_file.csv output_file.csv
```
- **`-i`**: Input file (CSV or Excel format with an `IP` column).
- : Output file (CSV or Excel format where results will be saved).

### Example
```bash
ipreputo -i sample_ips.xlsx -o results.csv
```

## 📜 Output Details
The output file will contain the following columns:
- **IP** – The analyzed IP address.
- **ISP** – Internet Service Provider.
- **Location** – Geographical location of the IP.
- **VirusTotal Malicious** – Count of malicious reports on VirusTotal.
- **AlienVault Pulse Count** – Number of threat pulses.
- **PulseDive Risk** – Risk level (Low/Medium/High).
- **AbuseIPDB Confidence Score** – Confidence score (0-100).
- **Category** – Final classification (**Malicious** / **Non-Malicious**).

## 🔥 ASCII Banner
When you run **IPREPUTO**, you will see this banner:
"""
██╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗████████╗ ██████╗ 
██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
██║██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║   ██║   ██║   ██║
██║██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║   ██║   ██║   ██║
██║██║     ██║  ██║███████╗██║     ╚██████╔╝   ██║   ╚██████╔╝
╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝    ╚═╝    ╚═════╝ 
"""

## 🛡 Requirements
- Python 3.7+
- `requests`, `pandas`, `openpyxl`


## 🤝 Contributing
Feel free to submit issues and pull requests.

---
Developed with ❤️ by [Anandhu S](https://github.com/anandhu2231)

