# app.py — Flask-HTTPAuth 装饰器模式
from flask import Flask, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

# ============================================
# 模拟用户数据库（存储哈希值）
# werkzeug 2.3+ 默认使用 scrypt 算法
# ============================================
users = {
    "admin": generate_password_hash("secret123"),
    "viewer": generate_password_hash("readonly456"),
}

# 打印哈希值，观察格式
for user, pw_hash in users.items():
    print(f"  {user}: {pw_hash}")
# 输出格式: scrypt:32768:8:1$<salt>$<hash>
# 对比 Node.js bcrypt 格式: $2b$12$<salt><hash>

# ============================================
# 验证回调 — Flask-HTTPAuth 的核心
# ============================================
@auth.verify_password
def verify_password(username, password):
    """
    Flask-HTTPAuth 自动完成:
    - 解析 Authorization Header
    - Base64 解码
    - 分割 username 和 password
    - 将它们传递给这个函数

    返回值:
    - truthy (如用户名字符串) → 认证成功，值会成为 auth.current_user()
    - None 或 False → 认证失败，自动返回 401
    """
    if username in users and check_password_hash(users[username], password):
        return username
    return None

@auth.error_handler
def auth_error(status):
    """自定义认证失败的响应格式"""
    return jsonify({"error": "Access denied"}), status

# ============================================
# 路由
# ============================================

# 公开端点
@app.route('/health')
def health():
    return jsonify({"status": "ok"})

# 受保护端点 — 用 @auth.login_required 装饰
@app.route('/api/data')
@auth.login_required
def get_data():
    return jsonify({
        "message": f"Hello, {auth.current_user()}!",
        "data": ["item1", "item2", "item3"]
    })

@app.route('/admin')
@auth.login_required
def admin():
    return jsonify({"message": "Admin area", "user": auth.current_user()})

if __name__ == '__main__':
    app.run(debug=True, port=5001)