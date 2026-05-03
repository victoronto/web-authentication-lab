# app.py — JWT Auth with Access + Refresh Token Rotation
import hashlib
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
import jwt  # PyJWT
import bcrypt

app = Flask(__name__)

# ============================================
# 1. 加载 RSA 密钥对
# ============================================
with open('private.pem', 'r') as f:
    PRIVATE_KEY = f.read()
with open('public.pem', 'r') as f:
    PUBLIC_KEY = f.read()

# ============================================
# 2. 数据库
# ============================================
DATABASE = 'jwt-auth.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            family_id TEXT NOT NULL,
            is_used INTEGER DEFAULT 0,
            is_revoked INTEGER DEFAULT 0,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')

    # 初始化用户
    cursor = conn.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        hash1 = bcrypt.hashpw(b'secret123', bcrypt.gensalt(12)).decode()
        hash2 = bcrypt.hashpw(b'readonly456', bcrypt.gensalt(12)).decode()
        conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                     ('admin@example.com', hash1, 'admin'))
        conn.execute('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                     ('viewer@example.com', hash2, 'viewer'))
        conn.commit()
        print('Users initialized')
    conn.close()

# ============================================
# 3. Token 生成
# ============================================
def generate_access_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': str(user['id']),
        'email': user['email'],
        'role': user['role'],
        'iat': now,
        'exp': now + timedelta(minutes=15),
        'iss': 'http://localhost:5001',
        'aud': 'http://localhost:5001',
    }
    # ★ 关键：显式指定算法
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')

def generate_refresh_token(user_id, family_id):
    token = secrets.token_hex(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    db = get_db()
    db.execute(
        'INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at) VALUES (?, ?, ?, ?)',
        (token_hash, user_id, family_id, expires_at)
    )
    db.commit()
    return token

# ============================================
# 4. JWT 验证装饰器
# ============================================
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Access token required'}), 401

        token = auth_header.split(' ')[1]
        try:
            # ★ 关键：显式指定允许的算法
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'],
                                 issuer='http://localhost:5001',
                                 audience='http://localhost:5001')
            g.user = {
                'id': int(payload['sub']),
                'email': payload['email'],
                'role': payload['role'],
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Access token expired', 'code': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid access token: {str(e)}'}), 401
        return f(*args, **kwargs)
    return decorated

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.user['role'] not in roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required': list(roles),
                    'current': g.user['role'],
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================
# 5. 路由
# ============================================
@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password required'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (data['email'],)).fetchone()

    if not user or not bcrypt.checkpw(data['password'].encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Invalid email or password'}), 401

    family_id = secrets.token_hex(16)
    access_token = generate_access_token(dict(user))
    refresh_token = generate_refresh_token(user['id'], family_id)

    print(f"Login: {user['email']}, family: {family_id}")
    return jsonify({
        'accessToken': access_token,
        'refreshToken': refresh_token,
        'expiresIn': 900,
        'tokenType': 'Bearer',
    })

@app.route('/auth/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    if not data or 'refreshToken' not in data:
        return jsonify({'error': 'Refresh token required'}), 400

    token_hash = hashlib.sha256(data['refreshToken'].encode()).hexdigest()
    db = get_db()
    stored = db.execute('SELECT * FROM refresh_tokens WHERE token_hash = ?', (token_hash,)).fetchone()

    if not stored:
        return jsonify({'error': 'Invalid refresh token'}), 401

    # Reuse Detection
    if stored['is_used'] or stored['is_revoked']:
        db.execute('UPDATE refresh_tokens SET is_revoked = 1 WHERE family_id = ?', (stored['family_id'],))
        db.commit()
        print(f"⚠️ Reuse detected! Family {stored['family_id']} revoked")
        return jsonify({
            'error': 'Refresh token reuse detected. All sessions revoked.',
            'code': 'TOKEN_REUSE',
        }), 401

    if datetime.fromisoformat(stored['expires_at']) < datetime.now(timezone.utc):
        return jsonify({'error': 'Refresh token expired'}), 401

    # 标记为已使用
    db.execute('UPDATE refresh_tokens SET is_used = 1 WHERE id = ?', (stored['id'],))

    user = db.execute('SELECT * FROM users WHERE id = ?', (stored['user_id'],)).fetchone()
    new_access = generate_access_token(dict(user))
    new_refresh = generate_refresh_token(user['id'], stored['family_id'])
    db.commit()

    return jsonify({
        'accessToken': new_access,
        'refreshToken': new_refresh,
        'expiresIn': 900,
        'tokenType': 'Bearer',
    })

@app.route('/api/profile')
@require_auth
def profile():
    return jsonify({'user': g.user})

@app.route('/api/notes')
@require_auth
def notes():
    return jsonify({
        'notes': [
            {'id': 1, 'title': 'JWT is stateless'},
            {'id': 2, 'title': 'PyJWT + RS256'},
        ],
        'user': g.user,
    })

@app.route('/api/admin/users')
@require_auth
@require_role('admin')
def admin_users():
    db = get_db()
    users = db.execute('SELECT id, email, role FROM users').fetchall()
    return jsonify({'users': [dict(u) for u in users]})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)