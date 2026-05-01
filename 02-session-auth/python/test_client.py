# test_client.py — 用 requests 测试完整的 Session Auth 流程
import requests

BASE_URL = 'http://localhost:5001'

# 使用 Session 对象 — 自动管理 Cookie（类似浏览器行为）
s = requests.Session()

# 1. 未登录
resp = s.get(f'{BASE_URL}/api/notes')
print(f'1. Before login: {resp.status_code} {resp.json()}')
# 401

# 2. 登录
resp = s.post(f'{BASE_URL}/login', json={
    'email': 'admin@example.com',
    'password': 'secret123',
})
print(f'2. Login: {resp.status_code} {resp.json()}')
# 200

# 查看 requests.Session 管理的 Cookie
print(f'   Cookies: {dict(s.cookies)}')
# {'session': 'some-session-id'}

# 3. 访问受保护端点（requests.Session 自动附带 Cookie）
resp = s.get(f'{BASE_URL}/api/notes')
print(f'3. After login: {resp.status_code} {resp.json()}')
# 200

# 4. 查看实际发送的 Cookie Header
resp = s.get(f'{BASE_URL}/api/profile')
print(f'4. Profile: {resp.json()}')
print(f'   Sent Cookie: {resp.request.headers.get("Cookie")}')

# 5. 登出
resp = s.post(f'{BASE_URL}/logout')
print(f'5. Logout: {resp.status_code} {resp.json()}')

# 6. 登出后访问
resp = s.get(f'{BASE_URL}/api/notes')
print(f'6. After logout: {resp.status_code} {resp.json()}')
# 401