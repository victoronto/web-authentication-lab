# test_client.py — 用 requests 库作为 HTTP 客户端
import requests
from requests.auth import HTTPBasicAuth

BASE_URL = "http://localhost:5001"

# 方式 1: 使用 HTTPBasicAuth 类
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=HTTPBasicAuth("admin", "secret123"))
print(f"Status: {resp.status_code}")
print(f"Body: {resp.json()}")

# 方式 2: 元组简写（效果完全相同）
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=("admin", "secret123"))
print(f"Body: {resp.json()}")

# 查看实际发送的 Authorization Header
print(f"Sent header: {resp.request.headers['Authorization']}")
# 输出: Basic YWRtaW46c2VjcmV0MTIz

# 验证: 解码这个 Base64 值
import base64
decoded = base64.b64decode("YWRtaW46c2VjcmV0MTIz").decode()
print(f"Decoded: {decoded}")
# 输出: admin:secret123

# 测试认证失败的情况
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=("admin", "wrongpassword"))
print(f"Failed status: {resp.status_code}")  # 401
print(f"Failed body: {resp.json()}")