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

def calculate_entropy(data):
    if not data: return 0.0
    entropy = 0.0
    counter = Counter(data)
    length = len(data)
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_features(file_path):
    features = [0.0] * 175
    try:
        with open(file_path, 'rb') as f:
            data = f.read(2 * 1024 * 1024)
        features[0] = os.path.getsize(file_path) / (1024 * 1024)
        features[1] = calculate_entropy(data)
        
        if file_path.lower().endswith(('.exe', '.dll')):
            try:
                pe = pefile.PE(data=data, fast_load=True)
                features[2] = pe.FILE_HEADER.NumberOfSections
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name and imp.name.decode(errors='ignore').lower() in ['virtualalloc', 'createremotethread', 'writeprocessmemory']:
                                features[3] = 1.0
                                break
            except pefile.PEFormatError:
                pass
        return features
    except Exception:
        return None

def async_upload(file_path, score, features, engine_type):
    def _upload():
        try:
            fake_hash = hashlib.sha256(f"{os.path.basename(file_path)}_{os.path.getsize(file_path)}".encode()).hexdigest()
            payload = {"hash": fake_hash, "score": score, "features": features, "engine": engine_type}
            req = urllib.request.Request(
                API_URL,
                data=json.dumps(payload).encode('utf-8'),
                method='POST',
                headers={'Content-Type': 'application/json', 'X-WindGrid-Token': API_TOKEN}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
    threading.Thread(target=_upload, daemon=True).start()

def scan_file(file_path, pe_model, pdf_model):
    features = extract_features(file_path)
    if not features: return

    tensor_features = torch.tensor([features], dtype=torch.float32)
    
    if file_path.lower().endswith('.pdf'):
        engine_name = "PDF"
        with torch.no_grad():
            score = pdf_model(tensor_features).item()
    else:
        engine_name = "PE"
        with torch.no_grad():
            score = pe_model(tensor_features).item()
    
    filename = os.path.basename(file_path)
    entropy = features[1]
    has_danger_api = features[3] == 1.0

    # ================= 核心检测逻辑 =================
    is_malicious = False
    is_warn = False
    reason = ""

    # 1. AI 引擎判定
    if score > 0.8:
        is_malicious = True
        reason = f"AI 判定"
    
    # 2. 熵值规则引擎
    elif entropy > 7.2:
        is_warn = True
        reason = f"高熵值({entropy:.2f})"
        
    # 3. 高危 API (pefile 解析结果)
    elif has_danger_api:
        is_warn = True
        reason = f"PE导入表命中高危API"

    # 4. 新增：字符串特征扫描 (专治低熵木马)
    if not is_malicious and not is_warn:
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(2 * 1024 * 1024).lower()
            
            # 这些是进程注入、下载执行的杀手锏 API 字符串
            high_risk_strs = [b'virtualalloc', b'createremotethread', b'writeprocessmemory', b'wscript.shell', b'urlmon', b'wininet']
            for s in high_risk_strs:
                if s in raw_data:
                    is_warn = True
                    reason = f"命中高危注入字符串({s.decode()})"
                    break
        except Exception:
            pass

    # ================= 打印输出 =================
    if is_malicious:
        print(f"\r\033[K\033[91m[拦截-{engine_name}] {filename} | AI: {score*100:.1f}% | \033[93m[已上报]\033[0m")
        async_upload(file_path, score, features, engine_name)
    elif is_warn:
        print(f"\r\033[K\033[93m[警告] {filename} | 特征: {reason}\033[0m")
    else:
        print(f"\r\033[K\033[92m[安全-{engine_name}] {filename} | AI: {score*100:.1f}% | 熵值: {entropy:.2f}\033[0m")

def format_time(seconds):
    if seconds < 60: return f"{int(seconds)}s"
    return f"{int(seconds // 60)}m {int(seconds % 60)}s"

def load_model(model_path):
    if not os.path.exists(model_path): return None
    state_dict = torch.load(model_path, map_location=torch.device('cpu'))
    
    weights = [v for k, v in state_dict.items() if 'weight' in k]
    biases = [v for k, v in state_dict.items() if 'bias' in k]
    
    model = nn.Sequential(
        nn.Linear(175, 128), nn.Linear(128, 64), nn.Linear(64, 1), nn.Sigmoid()
    )
    model[0].weight.data = weights[0]
    model[0].bias.data = biases[0]
    model[1].weight.data = weights[1]
    model[1].bias.data = biases[1]
    model[2].weight.data = weights[2]
    model[2].bias.data = biases[2]
    model.eval()
    return model

def main():
    if len(sys.argv) < 2: return
    target_path = sys.argv[1]
    
    print("[*] 正在加载双引擎模型...")
    pe_model = load_model("model_full.pth")
    pdf_model = load_model("WindGrid_PDF_Final.pth")
    print("[*] 引擎加载完毕！启动 AI + 熵值 + 字符串三重交叉复核...\n")

    if os.path.isfile(target_path):
        scan_file(target_path, pe_model, pdf_model)
    elif os.path.isdir(target_path):
        target_files = []
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.js', '.vbs', '.bat', '.pdf')):
                    target_files.append(os.path.join(root, file))
        
        total_files = len(target_files)
        if total_files == 0: return
        
        start_time = time.time()
        for index, file_path in enumerate(target_files):
            scan_file(file_path, pe_model, pdf_model)
            elapsed_time = time.time() - start_time
            processed = index + 1
            if processed > 0:
                avg_time = elapsed_time / processed
                eta = avg_time * (total_files - processed)
                print(f"\r\033[96m[进度] {processed}/{total_files} | 耗时: {format_time(elapsed_time)} | ETA: {format_time(eta)}\033[0m", end='', flush=True)

        print(f"\n\n\033[92m[✔] 扫描完成！总耗时: {time.time() - start_time:.2f} 秒。\033[0m")

if __name__ == "__main__":
    main()
