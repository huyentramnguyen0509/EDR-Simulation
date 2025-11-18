import pefile
import os
import sys
import re
import math # ĐÃ THÊM: Cần thiết để tính math.log2
from collections import Counter

# -------------------------
# HẰNG SỐ ĐỊNH NGHĨA DẤU HIỆU LOCKBIT 3.0
# -------------------------
MIN_ENTROPY = 6.3
MIN_SCORE_ALERT = 20

ANTI_DEBUG_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtGlobalFlags",
]

# LockBit 3.0 Loader Hex Patterns (Opcode) - Dùng wild card '.'
# re.compile(b'\xE8....\x8B\x40\x10\x8B\x40\x44\xC3', re.DOTALL)
INDIRECT_PEB_ACCESS = b'\x33\xC0\x40\xC1\xE0\x06\x8D\x40\xF0\x64\x8B\x00\xC3' 
HEX_TO_BIN_UPPER_CORE = b'\x66\x83\xF8\x41\x72.\x66\x83\xF8\x46\x77\x06\x66\x83\xE8\x37\xEB.' 
GET_CMD_BUFFER_CORE = b'\xE8....\x8B\x40\x10\x8B\x40\x44\xC3' 

SCORES = {
    "HIGH_ENTROPY": 10,
    "LOADER_SIG": 15,
    "ANTI_DEBUG": 10,
}

# -------------------------
# CÁC HÀM PHÂN TÍCH
# -------------------------

def calculate_shannon_entropy(data, size):
    """Tính toán Shannon Entropy chuẩn."""
    counts = Counter(data)
    entropy_val = 0
    if size > 0:
        for count in counts.values():
            p_i = count / size
            if p_i > 0:
                # SỬ DỤNG math.log2 ĐÃ SỬA LỖI
                entropy_val -= p_i * math.log2(p_i)
    return entropy_val

def analyze_file(file_path):
    score = 0
    results = []

    if not os.path.exists(file_path):
        return f"ERROR: File not found at path: {file_path}", 0

    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read()
        pe = pefile.PE(file_path, data=data)
    except Exception as e:
        return f"ERROR: Could not parse PE file or read data: {e}", 0

    # 1. KIỂM TRA ENTROPY (Mã hóa)
    results.append("[*] Checking High Entropy...")
    entropy_val = calculate_shannon_entropy(data, file_size)
    if entropy_val >= MIN_ENTROPY:
        results.append(f"[+] High Entropy detected ({entropy_val:.2f}) - Score: +{SCORES['HIGH_ENTROPY']}")
        score += SCORES["HIGH_ENTROPY"]

    # 2. KIỂM TRA DẤU HIỆU LOADER ASSEMBLY (Opcode)
    results.append("[*] Checking LockBit Loader signatures...")
    patterns_to_find = [
        re.compile(INDIRECT_PEB_ACCESS, re.DOTALL),
        re.compile(HEX_TO_BIN_UPPER_CORE, re.DOTALL), 
        re.compile(GET_CMD_BUFFER_CORE, re.DOTALL) 
    ]
    
    found_loader_sigs = 0
    for section in pe.sections:
        if section.Characteristics & 0x20: # Executable section
            data_sec = section.get_data()
            for regex_pat in patterns_to_find:
                if regex_pat.search(data_sec):
                    found_loader_sigs += 1
            
            if found_loader_sigs >= 2: 
                results.append(f"[+] LockBit Loader signature found ({found_loader_sigs}/3 Opcode matches) - Score: +{SCORES['LOADER_SIG']}")
                score += SCO