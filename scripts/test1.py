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

# File Metadata extraction
def get_file_info(filepath, min_length=5):
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

    return {
        'file size': str(info.st_size),
        'file owner': getpwuid(info.st_uid).pw_name,
        'file type': 'ELF' if str_result[0].startswith('ELF') else 'PE',
        'creation-time': str(datetime.fromtimestamp(info.st_ctime))[:19],
        'modified': str(datetime.fromtimestamp(info.st_mtime))[:19],
        'strings': str_result
    }


# Elf File Analysis
def elf_analysis(filepath):

    with open(filepath, 'rb') as f:
        elf_file = ELFFile(f)

        # Extracting and displaying the ELF header info
        print(f"ELF Class: {elf_file.header['e_ident']['EI_CLASS']}")
        print(f"ELF Machine (architecture): {elf_file.header['e_machine']}")

        # Extracting and displaying sections info
        print("\nSections:")
        for section in elf_file.iter_sections():
            print(f"{section.name}: {section['sh_type']}")

        # If the binary has symbols, display them
        symbol_tables = [s for s in elf_file.iter_sections() if isinstance(s, elftools.elf.sections.SymbolTableSection)]
        if symbol_tables:
            for symbol_table in symbol_tables:
                print(f"\nSymbols from {symbol_table.name}:")
                for symbol in symbol_table.iter_symbols():
                    print(f"{symbol.name}: {symbol['st_info']['type']}")


# Heuristic Analysis based on metadata
def heuristic_analysis(file_info):
    alerts = []
    
    # Example heuristic: Check if any IP-like patterns are found in embedded strings
    for s in file_info['strings']:
        if "192.168." in s:  # just a basic example
            alerts.append(f"Suspicious IP pattern found: {s}")
        #print(s)
    
    return alerts

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


def main():

    hash = {}
    total_virus_key = os.environ.get('VT_API_KEY')


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


    # Perform ELF analysis if file is an ELF binary
    if file_info['file type'] == 'ELF':
        print(colored("ELF Analysis: ", 'blue') )
        elf_analysis(filename)
        print()
    
    # Gather file hashes and display
    print(colored("File Hashes: ", 'blue') )
    for key, value in get_file_hash(filename).items():
        print(key + ": " + value)
        if key == 'SHA256':
            hash[key] = value
    print()

    # Perform heuristic analysis and display alerts
    alerts = heuristic_analysis(file_info)
    for alert in alerts:
        print(colored(alert, 'yellow'))
    print()

    # Check if file is packed
    print(colored("Packer Detection: ", 'blue') )
    packer = detect_packer(filename)
    if packer != 0:
        print(colored(f"File is packed with {packer}", 'red'))
    else:
        print(colored("File is not packed", 'green'))
    print()


    # VirusTotal report
    print(colored("VirusTotal Report: ", 'blue') )
    get_virustotal_report(total_virus_key, hash)

if __name__ == "__main__":
    main()
