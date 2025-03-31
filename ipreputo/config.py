import os
import json

CONFIG_FILE = os.path.expanduser("~/.ipreputo_config")

def load_config():
    """Load API keys from the config file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(config):
    """Save API keys to the config file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

def get_api_keys():
    """Prompt the user for API keys if not already saved."""
    config = load_config()
    if not config:
        config["VIRUSTOTAL_API_KEY"] = input("Enter VirusTotal API Key: ").strip()
        config["ALIENVAULT_API_KEY"] = input("Enter AlienVault API Key: ").strip()
        config["PULSEDIVE_API_KEY"] = input("Enter PulseDive API Key: ").strip()
        config["ABUSEIPDB_API_KEY"] = input("Enter AbuseIPDB API Key: ").strip()
        save_config(config)
    return config
