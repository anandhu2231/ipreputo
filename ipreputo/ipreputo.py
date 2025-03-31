import os
import sys
import pandas as pd
import requests
import threading
import time
from ipreputo.config import get_api_keys

# Load API Keys
API_KEYS = get_api_keys()
VIRUSTOTAL_API_KEY = API_KEYS["VIRUSTOTAL_API_KEY"]
ALIENVAULT_API_KEY = API_KEYS["ALIENVAULT_API_KEY"]
PULSEDIVE_API_KEY = API_KEYS["PULSEDIVE_API_KEY"]
ABUSEIPDB_API_KEY = API_KEYS["ABUSEIPDB_API_KEY"]

# ASCII Banner
ASCII_BANNER = """
██╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗████████╗ ██████╗ 
██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
██║██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║   ██║   ██║   ██║
██║██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║   ██║   ██║   ██║
██║██║     ██║  ██║███████╗██║     ╚██████╔╝   ██║   ╚██████╔╝
╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝    ╚═╝    ╚═════╝ 
"""
print(ASCII_BANNER)

# Loading spinner
loading = True
def spinner():
    while loading:
        for char in "|/-\\":
            sys.stdout.write(f"\rProcessing... {char}")
            sys.stdout.flush()
            time.sleep(0.1)

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if "data" in data:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0)
    except Exception as e:
        print(f"\nVirusTotal error for {ip}: {e}")
    return None

def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        return data.get("pulse_info", {}).get("count", 0)
    except Exception as e:
        print(f"\nAlienVault error for {ip}: {e}")
    return None

def check_pulsedive(ip):
    url = "https://pulsedive.com/api/info.php"
    params = {"key": PULSEDIVE_API_KEY, "indicator": ip}
    
    try:
        response = requests.get(url, params=params)
        data = response.json()
        return data.get("risk", "Unknown")
    except Exception as e:
        print(f"\nPulseDive error for {ip}: {e}")
    return None

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as e:
        print(f"\nAbuseIPDB error for {ip}: {e}")
    return None

def get_ip_info(ip):
    url = f"http://ip-api.com/json/{ip}?fields=isp,country,regionName,city"
    try:
        response = requests.get(url)
        data = response.json()
        return data.get("isp", "Unknown"), f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}"
    except Exception as e:
        print(f"\nIP Info error for {ip}: {e}")
    return "Unknown", "Unknown"

def categorize_ip(virustotal, alienvault, pulsedive, abuseipdb):
    if virustotal > 0 or alienvault > 0 or pulsedive == "High" or abuseipdb > 50:
        return "Malicious"
    return "Non-Malicious"

def process_ips(file_path, output_path):
    global loading
    loading = True
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.start()
    
    ext = os.path.splitext(file_path)[1]
    df = pd.read_csv(file_path) if ext == ".csv" else pd.read_excel(file_path)
    
    df.rename(columns=lambda x: x.strip(), inplace=True)
    if "IP" not in df.columns:
        df.rename(columns={"IP Address": "IP"}, inplace=True)
    
    if "IP" not in df.columns:
        raise ValueError("Column 'IP' not found in input file.")
    
    df["ISP"], df["Location"] = zip(*df["IP"].apply(get_ip_info))
    df["VirusTotal Malicious"] = df["IP"].apply(check_virustotal)
    df["AlienVault Pulse Count"] = df["IP"].apply(check_alienvault)
    df["PulseDive Risk"] = df["IP"].apply(check_pulsedive)
    df["AbuseIPDB Confidence Score"] = df["IP"].apply(check_abuseipdb)
    df["Category"] = df.apply(lambda row: categorize_ip(
        row["VirusTotal Malicious"], row["AlienVault Pulse Count"],
        row["PulseDive Risk"], row["AbuseIPDB Confidence Score"]
    ), axis=1)
    
    loading = False
    spinner_thread.join()
    
    if output_path.endswith(".csv"):
        df.to_csv(output_path, index=False)
    else:
        df.to_excel(output_path, index=False)
    
    print("\n✅ Results saved to", output_path)
