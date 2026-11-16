import torch
import numpy as np
import os

print("[*] 正在加载 V3 模型...")
# 先定义模型结构，跟训练时保持一致
class WindGridV3(torch.nn.Module):
    def __init__(self):
        super(WindGridV3, self).__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(1220, 256), torch.nn.ReLU(),
            torch.nn.Dropout(0.3),
            torch.nn.Linear(256, 64), torch.nn.ReLU(),
            torch.nn.Linear(64, 1), torch.nn.Sigmoid()
        )
    def forward(self, x):
        return self.net(x)

model = WindGridV3()
model.load_state_dict(torch.load("WindGrid_V3_Best.pth", map_location='cpu'))
model.eval()

print("[*] 开始进行 INT8 物理量化...")
quantized_dict = {}

for name, param in model.state_dict().items():
    # 提取权重的 numpy 数组
    weight_np = param.numpy()
    
    # 计算缩放因子 (将浮点数映射到 -127 到 127 之间)
    abs_max = np.max(np.abs(weight_np))
    if abs_max == 0:
        scale = 1.0
    else:
        scale = abs_max / 127.0
        
    # 量化
    weight_q = np.round(weight_np / scale).astype(np.int8)
    
    # 保存量化后的权重和缩放因子
    quantized_dict[f"{name}_q"] = weight_q
    quantized_dict[f"{name}_scale"] = np.array([scale], dtype=np.float32)

# 保存为压缩的 npz
np.savez_compressed("WindGrid_V3_Quantized.npz", **quantized_dict)

size_kb = os.path.getsize("WindGrid_V3_Quantized.npz") / 1024
print(f"[✔] 量化完成！体积缩小至: {size_kb:.2f} KB")
