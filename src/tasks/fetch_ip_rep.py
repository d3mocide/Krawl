from sqlalchemy import select
from typing import Optional
from database import get_database, DatabaseManager
from zoneinfo import ZoneInfo
from pathlib import Path
from datetime import datetime, timedelta
import re
import urllib.parse
from wordlists import get_wordlists
from config import get_config
from logger import get_app_logger
import requests
from sanitizer import sanitize_for_storage, sanitize_dict

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "fetch-ip-rep",
    "cron": "*/1 * * * *",
    "enabled": True,
    "run_when_loaded": True
}


def main():
    
    config = get_config()
    db_manager = get_database()
    app_logger = get_app_logger()

    accesses = db_manager.get_access_logs(limit=999999999)
    ips = {item['ip'] for item in accesses}

    for ip in ips:
        api_url = "https://iprep.lcrawl.com/api/iprep/"
        params = {
            "cidr": ip
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.get(api_url, headers=headers, params=params)
        payload = response.json()
        if payload["results"]:
            data = payload["results"][0]
            country_iso_code = data["geoip_data"]["country_iso_code"]
            asn = data["geoip_data"]["asn_autonomous_system_number"]
            asn_org = data["geoip_data"]["asn_autonomous_system_organization"]
            list_on = data["list_on"]
            sanitized_country_iso_code = sanitize_for_storage(country_iso_code, 3)
            sanitized_asn = sanitize_for_storage(asn, 100)
            sanitized_asn_org = sanitize_for_storage(asn_org, 100)
            sanitized_list_on = sanitize_dict(list_on, 100000)
            
            db_manager.update_ip_rep_infos(ip, sanitized_country_iso_code, sanitized_asn, sanitized_asn_org, sanitized_list_on)
        
    return