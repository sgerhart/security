import hashlib
import os
import sys
import requests


from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from datetime import datetime
from pwd import getpwuid

def get_file_info(filepath):

    info = os.stat(filepath)

    return {

        'file size': str(info.st_size),
        'file owner': getpwuid(info.st_uid).pw_name,
        'creation-time': str(datetime.fromtimestamp(info.st_ctime))[:19],
        'modified': str(datetime.fromtimestamp(info.st_mtime))[:19]
    }


def get_file_hash(filepath):
    
    BLOCK_SIZE = 65536
    
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BLOCK_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    return {
        'MD': md5.hexdigest(),
        'SHA1': sha1.hexdigest(),
        'SHA256': sha256.hexdigest()
    }

def get_virustotal_report(api_key,hashes):

   
    for key, value in hashes.items():
        url = f'https://www.virustotal.com/api/v3/files/{value}'
        headers = {'Accept': 'application/json', 'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        #response.raise_for_status()

        if response.status_code == 200:
            json_response = response.json()

            print("Magic - " + str(json_response['data']['attributes']['magic']) + "\n")
            
            
            harmless = json_response['data']['attributes']['last_analysis_stats']['harmless']
            print(f"Harmless Results - {harmless}")
            suspicious = json_response['data']['attributes']['last_analysis_stats']['suspicious']
            print(f"Suspicious Results- {suspicious}")
            malicious = json_response['data']['attributes']['last_analysis_stats']['malicious']
            print(f"Malicious Results - {malicious}")
            type_unsupported = json_response['data']['attributes']['last_analysis_stats']['type-unsupported']
            print(f"Type_Unsupported Results - {type_unsupported}")
            undetected = json_response['data']['attributes']['last_analysis_stats']['undetected']
            print(f"Undetect Results- {undetected}")

            last_analysis_results = json_response['data']['attributes']['last_analysis_results']

            for key, value in last_analysis_results.items():
                if value['category'] == 'malicious' or value['category'] == 'suspicious':
                    print(f"{key}: {value['result']}")
        


    
        else:
            print("Error: " + str(response.status_code))



def main():

    hash = {}
    total_virus_key = os.environ.get('VT_API_KEY')
    print(total_virus_key)
    if len(sys.argv) != 2:
        print("Usage: python3 test.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    print("File Info: " + filename + "\n")
    for key, value in get_file_info(filename).items():
        print(key + ": " + value)
    print()


    print("File Hashes: " + filename + "\n")
    for key, value in get_file_hash(filename).items():
        print(key + ": " + value)
        if key == 'SHA256':
            hash[key] = value
    print()

    print("VirusTotal Report: " + filename + "\n")
    get_virustotal_report(total_virus_key, hash)





if __name__ == "__main__":
    main()