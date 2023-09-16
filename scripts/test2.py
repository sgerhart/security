import hashlib
import os
import sys
import requests
import pefile
import elftools

from elftools.elf.elffile import ELFFile
from datetime import datetime
from pwd import getpwuid
from termcolor import colored  # You'll need to install termcolor: pip install termcolor


SUSPICIOUS_IMPORTS = ['VirtualAlloc', 'LoadLibrary', 'GetProcAddress']
OPENAI_API_URL = 'https://api.openai.com/v2/engines/davinci/completions'


# File Metadata extraction
def get_file_info(filepath, min_length=5):
    type = ""
    info = os.stat(filepath)
    
    # Extract embedded strings
    with open(filepath, 'rb') as file:
        str_result = []
        current_string = b""
        while True:
            byte = file.read(1)
            if byte == b"":
                break
            if 32 <= ord(byte) < 126:
                current_string += byte
            else:
                if len(current_string) > min_length:
                    str_result.append(current_string.decode(errors='replace'))
                current_string = b""

    # Extract header info
    with open(filepath, 'rb') as file:
        header = file.read(4)

        if header == b'\x7fELF':
            type = "ELF"
        elif header[:2] == b'MZ':
            type = "PE"
        else:
            return "Unknown file type"

    return {
        'file size': str(info.st_size),
        'file owner': getpwuid(info.st_uid).pw_name,
        'file type': type,
        'creation-time': str(datetime.fromtimestamp(info.st_ctime))[:19],
        'modified': str(datetime.fromtimestamp(info.st_mtime))[:19],
        'strings': str_result
    }


# PE File Analysis
def analyze_pe(file_path):
    suspicious_found = []
    pe = pefile.PE(file_path)

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name.decode('utf-8') in SUSPICIOUS_IMPORTS:
                suspicious_found.append(imp.name.decode('utf-8'))
    return suspicious_found

# ELF File Analysis
def analyze_elf(file_path):
    suspicious_found = []
    with open(file_path, 'rb') as f:
        elf_file = ELFFile(f)
        for section in elf_file.iter_sections():
            if isinstance(section, elftools.elf.sections.SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name in SUSPICIOUS_IMPORTS:
                        suspicious_found.append(symbol.name)
    return suspicious_found


# Improved VirusTotal reporting with colored outputs
def get_virustotal_report(api_key, hashes):

    i = 0

    for key, value in hashes.items():
        url = f'https://www.virustotal.com/api/v3/files/{value}'
        headers = {'Accept': 'application/json', 'x-apikey': api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            
            # Display results with color for better clarity
            print(colored(f"Magic - " + str(json_response['data']['attributes']['magic']), 'white'))
            malicious = json_response['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                print(colored(f"Malicious Results: {malicious}", 'red'))
            else:
                print(colored(f"Malicious Results: {malicious}", 'green'))

            last_analysis_results = json_response['data']['attributes']['last_analysis_results']
            print()

            # Get the top 5 AV results
            print(colored("Top 5 AV Results:", 'red'))

            for key, value in last_analysis_results.items():
                if i <= 5:
                    if value['category'] == 'malicious' or value['category'] == 'suspicious':
                        print(f"{key}: {value['result']}")
                    i += 1
            
        else:
            print("Error: " + str(response.status_code))

# Hashing
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

# Packer Detection
def detect_packer(filepath):
    
    try:
         pe = pefile.PE(filepath)

    except Exception as e:
        print(f"Error Reading PE: {e}")
        return 0

    suspicious_packer = ['ASPack', 'ASProtect', 'PECompact', 'PELock', 'PESpin', 'UPX', 'VMProtect', 'WinRAR', 'WinZip']

    for section in pe.sections:
        for s in suspicious_packer:
            if s in section.Name.decode('utf-8'):
                return s
    return None


def get_detail_from_chatgpt(api_key, string):
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    data = {
        'prompt': f'Provide details about the function or symbol: {string}',
        'max_tokens': 150
    }

    response = requests.post(OPENAI_API_URL, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()["choices"][0]["text"].strip()
    else:
        return f"Error: {response.text}"




def main():

    hash = {}
    suspicious_found = []
    total_virus_key = os.environ.get('VT_API_KEY')
    openai_key = os.environ.get('OPENAI_API_KEY')


    if len(sys.argv) != 2:
        print("Usage: python3 test.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    # Gather file info and display
    print(colored("File Information: ", 'blue') )
    file_info = get_file_info(filename)
    for key, value in file_info.items():
        if key != 'strings':
            print(f"{key}: {value}")
        # else:
        #     print(f"{key}:")
        #     for s in value:
        #         print(f"\t{s}")
    print()


    suspicious_found = []

    if file_info['file type'] == "PE":
        suspicious_found = analyze_pe(filename)
    elif file_info['file type'] == "ELF":
        suspicious_found = analyze_elf(filename)

    if suspicious_found:
        api_key = 'YOUR_OPENAI_API_KEY'
        for item in suspicious_found:
            details = get_detail_from_chatgpt(openai_key, item)
            print(f"{item}: {details}")
    else:
        print("No suspicious imports or symbols found.")

    
    # Gather file hashes and display
    print(colored("File Hashes: ", 'blue') )
    for key, value in get_file_hash(filename).items():
        print(key + ": " + value)
        if key == 'SHA256':
            hash[key] = value
    print()


    # Check if file is packed
    print(colored("Packer Detection: ", 'blue') )
    if file_info['file type'] != 'ELF':
        packer = detect_packer(filename)
        if packer != 0:
            print(colored(f"File is packed with {packer}", 'red'))
        else:
            print(colored("File is not packed", 'green'))
    else:
        print(colored("File is not packed", 'green'))
    print()


    # VirusTotal report
    print(colored("VirusTotal Report: ", 'blue') )
    get_virustotal_report(total_virus_key, hash)

if __name__ == "__main__":
    main()
