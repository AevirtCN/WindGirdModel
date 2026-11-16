# WindGrid Model

WindGrid is a malicious file detection system based on deep learning, using PyTorch neural network models to perform malware detection on PE and PDF files.

## Project Introduction

WindGrid utilizes neural network models to analyze file feature vectors, identifying potential malicious files through entropy calculation and feature extraction techniques. This project contains multiple versions of detection models, applicable to different file type detection scenarios.

## Main Features

- **PE File Detection**: Malware detection for Windows executable files
- **PDF File Detection**: Identification of malicious PDF documents
- **Feature Extraction**: Calculate file entropy and extract multi-dimensional feature vectors
- **Asynchronous Processing**: Support for asynchronous uploading of scan results

## Core Modules

### local_scanner.py

- `calculate_entropy(data)`: Calculate data entropy
- `extract_features(file_path)`: Extract file features
- `async_upload(file_path, score, features, engine_type)`: Asynchronously upload scan results
- `scan_file(file_path, pe_model, pdf_model)`: Scan a single file
- `load_model(model_path)`: Load pre-trained models

### local_scanner_v3.py

- `WindGridV3`: PyTorch neural network model class
- `extract_features_1220(file_path)`: Extract 1220-dimensional feature vector
- `scan_file(file_path, model)`: Scan file using V3 model

## Model Files

| Filename | Description |
|--------|------|
| WindGrid_V3_Best.pth | Best model for V3 version |
| WindGrid_PDF_Final.pth | Dedicated model for PDF detection |
| model_full.pth | Complete detection model |

## Usage

### Environment Dependencies

```bash
pip install torch pefile numpy aiohttp
```

### Scan Files

```python
from local_scanner import load_model, scan_file

# Load models
pe_model = load_model('WindGrid_V3_Best.pth')
pdf_model = load_model('WindGrid_PDF_Final.pth')

# Scan file
result = scan_file('path/to/file.exe', pe_model, pdf_model)
print(result)
```

## Technical Features

- Malware detection based on deep neural networks
- Multi-dimensional feature analysis (entropy, byte distribution, etc.)
- Supports specialized detection for two file types: PE and PDF
- Asynchronous processing mechanism improves scanning efficiency

## License

Please refer to the LICENSE file for detailed information.