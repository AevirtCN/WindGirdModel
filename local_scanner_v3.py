import os
import sys
import math
import time
import json
import hashlib
import urllib.request
import threading
from collections import Counter
import torch
import torch.nn as nn
import pefile

API_URL = "https://api.windgird.us.ci/api/report"
API_TOKEN = "windgrid-secret-2026"

class WindGridV3(nn.Module):
    def __init__(self):
        super(WindGridV3, self).__init__()
        self.net = nn.Sequential(
            nn.Linear(1220, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    def forward(self, x):
        return self.net(x)

def calculate_entropy(data):
    if not data: return 0.0
    entropy = 0.0
    counter = Counter(data)
    length = len(data)
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_features_1220(file_path):
    features_175 = [0.0] * 175
    try:
        with open(file_path, 'rb') as f:
            data = f.read(2 * 1024 * 1024)
        features_175[0] = os.path.getsize(file_path) / (1024 * 1024)
        features_175[1] = calculate_entropy(data)
        
        if file_path.lower().endswith(('.exe', '.dll')):
            try:
                pe = pefile.PE(data=data, fast_load=True)
                features_175[2] = pe.FILE_HEADER.NumberOfSections
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name and imp.name.decode(errors='ignore').lower() in ['virtualalloc', 'createremotethread', 'writeprocessmemory']:
                                features_175[3] = 1.0
                                break
            except pefile.PEFormatError:
                pass
        
        # 核心：补齐到 1220 维
        features_1220 = features_175 + [0.0] * (1220 - 175)
        return features_1220
    except Exception as e:
        print(f"[-] 读取失败: {os.path.basename(file_path)} - {e}")
        return None

def scan_file(file_path, model):
    features = extract_features_1220(file_path)
    if not features: return

    tensor_features = torch.tensor([features], dtype=torch.float32)
    with torch.no_grad():
        score = model(tensor_features).item()
    
    filename = os.path.basename(file_path)
    entropy = features[1]
    
    if score > 0.8:
        print(f"\r\033[K\033[91m[拦截-V3] {filename} | AI: {score*100:.1f}% | 熵值: {entropy:.2f}\033[0m")
    elif entropy > 7.2:
        print(f"\r\033[K\033[93m[警告] {filename} | 特征: 高熵值({entropy:.2f})\033[0m")
    else:
        print(f"\r\033[K\033[92m[安全-V3] {filename} | AI: {score*100:.1f}% | 熵值: {entropy:.2f}\033[0m")

def main():
    if len(sys.argv) < 2: return
    target_path = sys.argv[1]
    
    print("[*] 正在加载 WindGrid V3 (1220维) 模型...")
    model = WindGridV3()
    if not os.path.exists("WindGrid_V3_Best.pth"):
        print("[-] 找不到模型文件！")
        return
    model.load_state_dict(torch.load("WindGrid_V3_Best.pth", map_location=torch.device('cpu')))
    model.eval()
    
    print("[*] 引擎加载完毕！开始扫描...\n")
    
    target_files = []
    if os.path.isfile(target_path):
        target_files.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.js', '.vbs', '.bat')):
                    target_files.append(os.path.join(root, file))
    
    print(f"[*] 共发现 {len(target_files)} 个目标文件，开始逐个扫描...")
    for file_path in target_files:
        scan_file(file_path, model)

if __name__ == "__main__":
    main()
