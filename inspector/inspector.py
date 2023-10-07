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
                    vt_report = f"VirusTotal Report: https://www.virustotal.com/gui/file/{resource_id}"
            except Exception as e:
                print(f"Error submitting file to VirusTotal: {e}")
        return vt_report

# def hybrid_virus_report(file_path):
#         ha_report = None
#         ha_api_key = os.getenv('HYBRID_ANALYSIS_API_KEY')
        
#         if ha_api_key:
#             url = "https://www.hybrid-analysis.com/api/v4/quick-scan/file"
#             files = ('file=@' + str((file_path, open(file_path, 'rb'))),'scan_type=all')
#             print(files)
#             headers = {
#                 "api-key": ha_api_key,
#             }
#             try:
#                 response = requests.post(url, headers=headers, files=files)
#                 print(response.status_code)
#                 if response.status_code == 200:
#                     data = response.json()
#                     print(data)
#                     analysis_id = data['response']['job_id']
#                     ha_report = f"Hybrid Analysis Report: https://www.hybrid-analysis.com/sample/{analysis_id}"
#             except Exception as e:
#                 print(f"Error submitting file to Hybrid Analysis: {e}")
#         return ha_report
        

# identify file type
def identify_file_type(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read the first few bytes (commonly 8-16 bytes)
            file_signature = file.read(16)

        # Check for specific magic bytes or patterns
        if file_signature.startswith(b'\x4D\x5A'):  # MZ header for Windows PE executable
            return "Windows PE Executable"
        elif file_signature.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):  # OLE file
            return "OLE Document (e.g., MS Office)"
        elif file_signature.startswith(b'\x50\x4B\x03\x04'):  # Zip archive (common in MS Office documents)
            return "MS Office Document (ZIP format)"
        elif file_signature.startswith(b'\x3C\x3F\x78\x6D\x6C'):  # XML or HTML file (common in VBS)
            return "XML/HTML File (e.g., VBS Script)"
        else:
            return "Unknown File Type"

    except Exception as e:
        print(f"Error identifying file type: {e}")

def calculate_entropy(data):
    entropy = 0
    if data:
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
    return entropy


def pe_analysis(file_path):
    try:
        pe = pefile.PE(file_path)
        pe_info = {
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "NumberOfSymbols": pe.FILE_HEADER.NumberOfSymbols,
            "Machine": hex(pe.FILE_HEADER.Machine),
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Characteristics": hex(pe.FILE_HEADER.Characteristics),
            "DLL": pe.OPTIONAL_HEADER.DllCharacteristics,
            "Entropy": round(pe.sections[0].get_entropy(),),
        }


        # Check for suspicious imports
        suspicious_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    if imp.name.decode('utf-8') in SUSPICIOUS_PE_IMPORTS:
                        suspicious_imports.append(imp.name.decode('utf-8'))

        if suspicious_imports: 
            pe_info["Suspicious Imports"] = suspicious_imports
        


        # iterate through the PE sections and print the section information
        section_info = []
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            virtual_size = section.Misc_VirtualSize
            virtual_address = section.VirtualAddress
            raw_size = section.SizeOfRawData
            characteristics = hex(section.Characteristics)
            entropy = round(section.get_entropy(),3)
    
            section_info.append({
                "Name": section_name,
                "VirtualSize": virtual_size,
                "VirtualAddress": virtual_address,
                "RawSize": raw_size,
                "Characteristics": characteristics,
                "Entropy": entropy,
            })

        pe_info["Sections"] = section_info

        # Check for suspicious sections
        suspicious_sections = []
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_WRITE and section.IMAGE_SCN_MEM_EXECUTE:
                suspicious_sections.append(section.Name.decode('utf-8'))
            elif section.IMAGE_SCN_MEM_WRITE and section.IMAGE_SCN_MEM_READ:
                suspicious_sections.append(section.Name.decode('utf-8'))
            elif section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_READ:
                suspicious_sections.append(section.Name.decode('utf-8'))
            elif section.IMAGE_SCN_MEM_WRITE and section.IMAGE_SCN_MEM_READ and section.IMAGE_SCN_MEM_EXECUTE:
                suspicious_sections.append(section.Name.decode('utf-8'))

        if suspicious_sections:
            pe_info["Suspicious Sections"] = suspicious_sections



        return pe_info
    
    except Exception as e:
        print(f"Error reading PE: {e}")
        return None



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

        static_info = {}

        # Identify the file type
        file_type = identify_file_type(file_path)


        if file_type == "Windows PE Executable":

            static_info = {
                "File Type": file_type,
                "PE Analysis": pe_analysis(file_path),
            }
            
            # Calculate hashes
            hashes = calculate_hashes(file_path)

            # Use the 'file' command to identify the file type
            magic_instance = magic.Magic()
            file_type = magic_instance.from_file(file_path)

       
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

        # # Checking hybrid analysis for posture of the file
        # static_info["Hybrid Analysis"] = hybrid_virus_report(file_path)

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

    # magic_instance = magic.Magic()
    # file_type = magic_instance.from_file(file_path)
    # print(file_type)



    


if __name__ == "__main__":
    main()