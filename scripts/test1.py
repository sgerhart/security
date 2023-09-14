import hashlib
import os
import sys
import requests

from datetime import datetime
from pwd import getpwuid
from termcolor import colored  # You'll need to install termcolor: pip install termcolor

# File Metadata extraction
def get_file_info(filepath):
    info = os.stat(filepath)
    
    # Extract embedded strings
    with open(filepath, 'r', errors='replace') as file:
        strings = file.read()
    strings = list(filter(lambda s: len(s) > 4, strings.split()))

    return {
        'file size': str(info.st_size),
        'file owner': getpwuid(info.st_uid).pw_name,
        'creation-time': str(datetime.fromtimestamp(info.st_ctime))[:19],
        'modified': str(datetime.fromtimestamp(info.st_mtime))[:19],
        'strings': strings
    }

# Heuristic Analysis based on metadata
def heuristic_analysis(file_info):
    alerts = []
    
    # Example heuristic: Check if any IP-like patterns are found in embedded strings
    for s in file_info['strings']:
        if "192.168." in s:  # just a basic example
            alerts.append(f"Suspicious IP pattern found: {s}")
    
    return alerts

# Improved VirusTotal reporting with colored outputs
def get_virustotal_report(api_key, hashes):
    for key, value in hashes.items():
        url = f'https://www.virustotal.com/api/v3/files/{value}'
        headers = {'Accept': 'application/json', 'x-apikey': api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            
            # Display results with color for better clarity
            malicious = json_response['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                print(colored(f"Malicious Results: {malicious}", 'red'))
            else:
                print(colored(f"Malicious Results: {malicious}", 'green'))
            
            # Add more colored outputs as needed...
        else:
            print("Error: " + str(response.status_code))

def main():
    hash = {}
    total_virus_key = os.environ.get('VT_API_KEY')
    if len(sys.argv) != 2:
        print("Usage: python3 test.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    # Gather file info and display
    file_info = get_file_info(filename)
    for key, value in file_info.items():
        if key != 'strings':
            print(f"{key}: {value}")

    # Perform heuristic analysis and display alerts
    alerts = heuristic_analysis(file_info)
    for alert in alerts:
        print(colored(alert, 'yellow'))

    # VirusTotal report
    for key, value in get_file_hash(filename).items():
        if key == 'SHA256':
            hash[key] = value
    get_virustotal_report(total_virus_key, hash)

if __name__ == "__main__":
    main()
