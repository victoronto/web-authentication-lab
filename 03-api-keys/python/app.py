# app.py — 完整的 API Key 认证系统
import sqlite3
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter

app = Flask(__name__)

# ============================================
# 1. 初始化 SQLite 数据库
# ============================================
DATABASE = 'apikeys.db'

def get_db():
    """每个请求使用一个数据库连接"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # 让查询结果像 dict 一样访问
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """创建表结构"""
    conn = sqlite3.connect(DATABASE)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            name TEXT DEFAULT 'default',
            created_at TEXT DEFAULT (datetime('now')),
            revoked_at TEXT DEFAULT NULL,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (key_id) REFERENCES api_keys(id)
        );
    ''')
    conn.close()

# ============================================
# 2. API Key 生成与哈希
# ============================================
def generate_api_key():
    """
    生成密码学安全的 API Key
    secrets.token_hex(32) 生成 32 字节（64 个 hex 字符）的随机数
    """
    random_part = secrets.token_hex(32)
    return f'ak_live_{random_part}'

def hash_api_key(key):
    """SHA-256 哈希（理由见 Node.js Part 中的解释）"""
    return hashlib.sha256(key.encode()).hexdigest()

def get_key_prefix(key):
    """提取前 16 个字符作为前缀"""
    return key[:16]

# ============================================
# 3. API Key 验证装饰器
# ============================================
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('x-api-key')

        if not api_key:
            return jsonify({
                'error': 'API key required',
                'hint': 'Include your API key in the x-api-key header',
            }), 401

        key_hash = hash_api_key(api_key)
        db = get_db()
        key_record = db.execute(
            'SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1 AND revoked_at IS NULL',
            (key_hash,)
        ).fetchone()

        if not key_record:
            return jsonify({'error': 'Invalid or revoked API key'}), 401

        # 挂到 g 对象上（Flask 的请求级全局变量）
        g.api_key = dict(key_record)
        return f(*args, **kwargs)
    return decorated

# ============================================
# 4. 用量记录
# ============================================
def log_usage(key_id, endpoint, method, status_code):
    db = get_db()
    db.execute(
        'INSERT INTO usage_logs (key_id, endpoint, method, status_code) VALUES (?, ?, ?, ?)',
        (key_id, endpoint, method, status_code)
    )
    db.commit()

# ============================================
# 5. Rate Limiting（Per-Key）
# ============================================
def get_api_key_or_ip():
    """Flask-Limiter 的 key function：优先用 API Key，没有就用 IP"""
    api_key = request.headers.get('x-api-key')
    if api_key:
        return hash_api_key(api_key)
    return request.remote_addr

limiter = Limiter(
    get_api_key_or_ip,
    app=app,
    default_limits=['100 per hour'],
    storage_uri='memory://',  # 开发环境用内存，生产环境用 Redis
)

# ============================================
# 6. 路由
# ============================================

@app.route('/health')
@limiter.exempt
def health():
    return jsonify({'status': 'ok'})

# Developer 注册
@app.route('/developer/register', methods=['POST'])
@limiter.exempt
def register():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'Email required'}), 400

    email = data['email']
    key_name = data.get('keyName', 'default')

    api_key = generate_api_key()
    key_hash = hash_api_key(api_key)
    key_prefix = get_key_prefix(api_key)

    db = get_db()
    db.execute(
        'INSERT INTO api_keys (owner_email, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)',
        (email, key_prefix, key_hash, key_name)
    )
    db.commit()

    print(f'New API Key registered for {email}: {key_prefix}...')

    return jsonify({
        'message': 'API key created successfully',
        'apiKey': api_key,
        'prefix': key_prefix,
        'warning': 'Save this key now! It cannot be retrieved later.',
    }), 201

# 受保护端点
@app.route('/api/weather')
@limiter.limit('100 per hour')
@require_api_key
def weather():
    city = request.args.get('city', 'Toronto')
    status_code = 200
    response = jsonify({
        'city': city,
        'temperature': '18°C',
        'condition': 'Partly Cloudy',
        'requestedBy': g.api_key['owner_email'],
        'keyPrefix': g.api_key['key_prefix'],
    })
    log_usage(g.api_key['id'], '/api/weather', 'GET', status_code)
    return response

@app.route('/api/forecast')
@limiter.limit('100 per hour')
@require_api_key
def forecast():
    response = jsonify({
        'forecast': [
            {'day': 'Monday', 'high': '20°C', 'low': '12°C'},
            {'day': 'Tuesday', 'high': '22°C', 'low': '14°C'},
        ],
        'requestedBy': g.api_key['owner_email'],
    })
    log_usage(g.api_key['id'], '/api/forecast', 'GET', 200)
    return response

# 用量统计
@app.route('/developer/usage')
@require_api_key
def usage():
    db = get_db()
    stats = db.execute('''
        SELECT COUNT(*) as total_requests,
               MIN(timestamp) as first_request,
               MAX(timestamp) as last_request
        FROM usage_logs WHERE key_id = ?
    ''', (g.api_key['id'],)).fetchone()

    recent = db.execute('''
        SELECT endpoint, method, status_code, timestamp
        FROM usage_logs WHERE key_id = ?
        ORDER BY timestamp DESC LIMIT 10
    ''', (g.api_key['id'],)).fetchall()

    return jsonify({
        'keyPrefix': g.api_key['key_prefix'],
        'stats': dict(stats),
        'recentRequests': [dict(r) for r in recent],
    })

# 吊销
@app.route('/developer/revoke', methods=['POST'])
@require_api_key
def revoke():
    db = get_db()
    db.execute(
        "UPDATE api_keys SET is_active = 0, revoked_at = datetime('now') WHERE id = ?",
        (g.api_key['id'],)
    )
    db.commit()
    print(f"API Key revoked: {g.api_key['key_prefix']}...")
    return jsonify({
        'message': 'API key revoked successfully',
        'prefix': g.api_key['key_prefix'],
    })

# 轮换
@app.route('/developer/rotate', methods=['POST'])
@require_api_key
def rotate():
    old_prefix = g.api_key['key_prefix']

    new_api_key = generate_api_key()
    new_key_hash = hash_api_key(new_api_key)
    new_key_prefix = get_key_prefix(new_api_key)

    db = get_db()
    db.execute(
        'INSERT INTO api_keys (owner_email, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)',
        (g.api_key['owner_email'], new_key_prefix, new_key_hash,
         f"{g.api_key['name']} (rotated)")
    )
    db.commit()

    print(f'API Key rotated: {old_prefix}... → {new_key_prefix}...')

    return jsonify({
        'message': 'New API key generated. Old key is still active for a grace period.',
        'newApiKey': new_api_key,
        'newPrefix': new_key_prefix,
        'oldPrefix': old_prefix,
        'warning': 'Save the new key now!',
    }), 201

# ============================================
# 启动
# ============================================
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)