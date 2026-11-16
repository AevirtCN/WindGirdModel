# WindGrid Model

WindGrid 是一个基于深度学习的恶意文件检测系统，使用 PyTorch 神经网络模型对 PE 文件和 PDF 文件进行恶意软件检测。

## 项目简介

WindGrid 采用神经网络模型分析文件的特征向量，通过熵值计算和特征提取技术识别潜在恶意文件。该项目包含多个版本的检测模型，适用于不同的文件类型检测场景。

## 主要功能

- **PE 文件检测**: 对 Windows 可执行文件进行恶意软件检测
- **PDF 文件检测**: 识别恶意 PDF 文档
- **特征提取**: 计算文件熵值并提取多维特征向量
- **异步处理**: 支持异步上传扫描结果

## 核心模块

### local_scanner.py

- `calculate_entropy(data)`: 计算数据熵值
- `extract_features(file_path)`: 提取文件特征
- `async_upload(file_path, score, features, engine_type)`: 异步上传扫描结果
- `scan_file(file_path, pe_model, pdf_model)`: 扫描单个文件
- `load_model(model_path)`: 加载预训练模型

### local_scanner_v3.py

- `WindGridV3`: PyTorch 神经网络模型类
- `extract_features_1220(file_path)`: 提取1220维特征向量
- `scan_file(file_path, model)`: 使用 V3 模型扫描文件

## 模型文件

| 文件名 | 说明 |
|--------|------|
| WindGrid_V3_Best.pth | V3 版本最佳模型 |
| WindGrid_PDF_Final.pth | PDF 检测专用模型 |
| model_full.pth | 完整检测模型 |

## 使用方法

### 环境依赖

```bash
pip install torch pefile numpy aiohttp
```

### 扫描文件

```python
from local_scanner import load_model, scan_file

# 加载模型
pe_model = load_model('WindGrid_V3_Best.pth')
pdf_model = load_model('WindGrid_PDF_Final.pth')

# 扫描文件
result = scan_file('path/to/file.exe', pe_model, pdf_model)
print(result)
```

## 技术特点

- 基于深度神经网络的恶意软件检测
- 多维度特征分析（熵值、字节分布等）
- 支持 PE 和 PDF 两种文件类型的专项检测
- 异步处理机制提高扫描效率

## 许可证

请查看 LICENSE 文件了解详细信息。