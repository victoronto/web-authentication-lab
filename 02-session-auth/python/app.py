# app.py — Flask-Session + Redis + CSRF 保护
import time
from datetime import timedelta
from functools import wraps
from flask import Flask, session, request, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_bcrypt import Bcrypt
import redis

app = Flask(__name__)

# ============================================
# 配置
# ============================================
app.config.update(
    SECRET_KEY='change-me-to-a-strong-random-string',

    # Flask-Session 配置
    SESSION_TYPE='redis',
    SESSION_REDIS=redis.Redis(host='192.168.215.1', port=6379, db=0),
    SESSION_PERMANENT=True,
    SESSION_KEY_PREFIX='session:',
    SESSION_SERIALIZATION_FORMAT='msgpack',  # Flask-Session 0.7+ 默认
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Idle timeout

    # Cookie 安全属性
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,        # 开发环境 False，生产环境 True
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='session',      # 自定义 Cookie 名称
)

sess = Session(app)
bcrypt_ext = Bcrypt(app)
csrf = CSRFProtect(app)

# ============================================
# 模拟用户数据库
# ============================================
users_db = {}

def init_users():
    users_db['admin@example.com'] = {
        'id': 1,
        'email': 'admin@example.com',
        'password_hash': bcrypt_ext.generate_password_hash('secret123').decode('utf-8'),
        'role': 'admin',
    }
    users_db['viewer@example.com'] = {
        'id': 2,
        'email': 'viewer@example.com',
        'password_hash': bcrypt_ext.generate_password_hash('readonly456').decode('utf-8'),
        'role': 'viewer',
    }
    print('Users initialized')

# ============================================
# 认证装饰器
# ============================================
def require_auth(f):
    """检查用户是否已登录"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated. Please login first.'}), 401
        return f(*args, **kwargs)
    return decorated

# ============================================
# Absolute Timeout 检查
# ============================================
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 小时（秒）

@app.before_request
def check_absolute_timeout():
    if 'user_id' in session:
        login_time = session.get('_login_time', 0)
        if time.time() - login_time > ABSOLUTE_TIMEOUT:
            session.clear()
            return jsonify({'error': 'Session expired (absolute timeout)'}), 401

# ============================================
# CSRF 错误处理
# ============================================
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'error': f'CSRF validation failed: {e.description}'}), 400

# ============================================
# 路由
# ============================================

# 公开端点
@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

# 获取 CSRF Token（登录后，在发送 POST 请求之前调用）
@app.route('/csrf-token')
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrfToken': token})

# 登录（豁免 CSRF，因为用户还没登录）
@csrf.exempt
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password required'}), 400

    email = data['email']
    password = data['password']
    user = users_db.get(email)

    if not user or not bcrypt_ext.check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid email or password'}), 401

    # ★ 关键：清除旧 Session 数据
    session.clear()

    # 写入用户数据到 Session（先写数据，再 regenerate）
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']
    session['_login_time'] = time.time()

    # ★ 关键：Regenerate Session ID，防御 Session Fixation
    # Flask-Session 0.8.0 内置了 regenerate() 方法
    # 注意：Session 必须非空才能 regenerate（空 dict 是 falsy，会导致静默失败！）
    # 所以上面先写入数据，然后再 regenerate
    app.session_interface.regenerate(session)

    print(f'Login: {email}, session regenerated')
    return jsonify({
        'message': 'Login successful',
        'user': {'id': user['id'], 'email': user['email'], 'role': user['role']},
    })

# 登出
@csrf.exempt  # 简化测试，生产环境应该要求 CSRF Token
@app.route('/logout', methods=['POST'])
def logout():
    email = session.get('email', 'unknown')
    session.clear()
    print(f'Logout: {email}')
    return jsonify({'message': 'Logged out successfully'})

# 受保护端点
@app.route('/api/profile')
@require_auth
def profile():
    return jsonify({
        'user_id': session['user_id'],
        'email': session['email'],
        'role': session['role'],
        'login_time': session.get('_login_time'),
    })

@app.route('/api/notes')
@require_auth
def get_notes():
    return jsonify({
        'notes': [
            {'id': 1, 'title': 'Flask-Session 学习', 'body': 'Redis 作为 Session Store'},
            {'id': 2, 'title': 'CSRF 防护', 'body': 'Flask-WTF CSRFProtect'},
        ],
        'user': session['email'],
    })

# 创建笔记（POST — 需要 CSRF Token）
@app.route('/api/notes', methods=['POST'])
@require_auth
def create_note():
    data = request.get_json()
    return jsonify({'message': 'Note created', 'note': data}), 201

# 调试端点
@app.route('/debug/session')
@require_auth
def debug_session():
    return jsonify({
        'session_data': {
            'user_id': session.get('user_id'),
            'email': session.get('email'),
            'role': session.get('role'),
            'login_time': session.get('_login_time'),
        },
    })

# ============================================
# 启动
# ============================================
if __name__ == '__main__':
    init_users()
    # 注意 port 不要用 5000（macOS 的 AirPlay Receiver 占用了 5000）
    # Module 01 你已经踩过这个坑了
    app.run(debug=True, port=5001)