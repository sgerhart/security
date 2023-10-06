import hashlib
import os
import subprocess
import sys
import pefile 
import magic
import requests 



total_virus_key = ""
hybrid_virus_key = ""

SUSPICIOUS_PE_IMPORTS = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
    "VirtualFree", "LoadLibrary", "GetProcAddress", "LdrLoadDll", "CreateFile",
    "WriteFile", "ReadFile", "DeleteFile", "CreateProcess", "OpenProcess",
    "TerminateProcess", "InjectThread", "WSASocket", "connect", "send", "recv",
    "InternetOpen", "InternetOpenUrl", "RegOpenKey", "RegSetValue", "RegCreateKey",
    "RegDeleteKey", "SetWindowsHookEx", "GetKeyState", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "OpenService", "StartService", "CreateService", "DeleteService"
]


def total_virus_report(file_path):
    # Submit the file to VirusTotal
        print("In total_virus_report")

        vt_api_key = os.getenv('VT_API_KEY')

        vt_report = None
        if vt_api_key:
            url = "https://www.virustotal.com/api/v3/files"
            headers = {
                "x-apikey": vt_api_key,
                "accept": "application/json",
                
            }
            files = {'file': (file_path, open(file_path, 'rb'))}
            try:
                response = requests.post(url, headers=headers, files=files)
                if response.status_code == 200:
                    data = response.json()
                    resource_id = data['data']['id']
                    print(data)
                    vt_report = f"VirusTotal Report: https://www.virustotal.com/gui/file/{resource_id}"
            except Exception as e:
                print(f"Error submitting file to VirusTotal: {e}")
        return vt_report

def hybrid_virus_report(file_path, ha_api_key):
        ha_report = None
        if ha_api_key:
            url = "https://www.hybrid-analysis.com/api/v4/quick-scan/file"
            headers = {
                "api-key": HA_API_KEY
            }
            files = {'file': (file_path, open(file_path, 'rb'))}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                data = response.json()
                print(data)
                analysis_id = data['response']['job_id']
                ha_report = f"Hybrid Analysis Report: https://www.hybrid-analysis.com/sample/{analysis_id}"

            return ha_report
        



# Calculate md5, sha1, sha256 hashes of a file
def calculate_hashes(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()

    return md5_hash, sha1_hash, sha256_hash


# Packer Detection
def detect_packer(file_path):
    
    try:
         pe = pefile.PE(file_path)

    except Exception as e:
        print(f"Error Reading PE: {e}")
        return 0

    suspicious_packer = ['ASPack', 'ASProtect', 'PECompact', 'PELock', 'PESpin', 'UPX', 'VMProtect', 'WinRAR', 'WinZip']

    for section in pe.sections:
        for s in suspicious_packer:
            if s in section.Name.decode('utf-8'):
                return s
    return None


def static_analysis(file_path, min_length=4):
    try:
        # Calculate hashes

        hashes = calculate_hashes(file_path)

        # Use the 'file' command to identify the file type
        magic_instance = magic.Magic()
        file_type = magic_instance.from_file(file_path)
        static_info = {
            "File Information": file_type,
            "MD5 Hash": hashes[0],
            "SHA1 Hash": hashes[1],
            "SHA256 Hash": hashes[2]
        }
       

        # Analyze Windows PE file format
        pe = pefile.PE(file_path)
        static_info["PE Analysis"] = {
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        }
        # Add more PE analysis as needed


        # Extract static strings from the binary
        str_result = []
        with open(file_path, 'rb') as file:
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
            
        static_info["Strings"] = str_result


        # Detect packer
        packer = detect_packer(file_path)

        if packer:
            static_info["Packer"] = packer
        else:
            static_info["Packer"] = "None"

        # Checking virus total for posture of the file
        static_info["Virus Total"] = total_virus_report(file_path)

        return static_info

  
    except Exception as e:
        print(f"Static analysis error: {str(e)}")
        return None



def main():

    hash = {}
    suspicious_found = []
    strings_found = []
    

    # Get API Keys from environment variables (export API_KEY=xxxxx)
    

    hybrid_virus_key = os.getenv('HYBRID_ANALYSIS_API_KEY')

    #openai_key = os.environ.get('OPENAI_API_KEY')


    if len(sys.argv) != 2:
        print("Usage: python3 inspector.py <filename>")
        sys.exit(1)

    file_path = sys.argv[1]

    print(f"Analyzing {file_path}...")
    print(f"Static Analysis Results:\n")
    for key, value in static_analysis(file_path).items():
        if key == "PE Analysis":
            print("PE Analysis: ")
            for k, v in value.items():
                print(f"     {k}: {v}")
        else:
            print(f"{key}: {value}")

    


if __name__ == "__main__":
    main()