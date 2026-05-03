// server.js — JWT Auth with Access + Refresh Token Rotation
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());
const PORT = 3000;

// ============================================
// 1. 加载 RSA 密钥对
// ============================================
const privateKeyPem = fs.readFileSync('private.pem', 'utf8');
const publicKeyPem = fs.readFileSync('public.pem', 'utf8');

let privateKey, publicKey;

async function loadKeys() {
    privateKey = await importPKCS8(privateKeyPem, 'RS256');
    publicKey = await importSPKI(publicKeyPem, 'RS256');
    console.log('RSA keys loaded');
}

// ============================================
// 2. 初始化数据库（存储用户和 Refresh Token）
// ============================================
const db = new Database('jwt-auth.db');
db.pragma('journal_mode = WAL');

db.exec(`
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
`);

// 初始化用户
async function initUsers() {
    const existing = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (existing.count === 0) {
        const hash1 = await bcrypt.hash('secret123', 12);
        const hash2 = await bcrypt.hash('readonly456', 12);
        db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run('admin@example.com', hash1, 'admin');
        db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run('viewer@example.com', hash2, 'viewer');
        console.log('Users initialized');
    }
}

// ============================================
// 3. Token 生成函数
// ============================================

/**
 * 签发 Access Token（短生命周期，包含用户信息）
 */
async function generateAccessToken(user) {
    return await new SignJWT({
        sub: String(user.id),
        email: user.email,
        role: user.role,
    })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime('15m')  // 15 分钟过期
        .setIssuer('http://localhost:3000')
        .setAudience('http://localhost:3000')
        .sign(privateKey);
}

/**
 * 生成 Refresh Token（长生命周期，存数据库）
 *
 * Refresh Token 不是 JWT！它是一个普通的随机字符串。
 * 为什么？因为 Refresh Token 需要能被服务端吊销（有状态）。
 * 如果用 JWT 做 Refresh Token，就回到了"签发后无法撤销"的老问题。
 */
function generateRefreshToken(userId, familyId) {
    const token = crypto.randomBytes(64).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 天

    db.prepare(`
    INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(tokenHash, userId, familyId, expiresAt);

    return token;
}

// ============================================
// 4. JWT 验证 Middleware
// ============================================
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Access token required',
            hint: 'Include "Authorization: Bearer <token>" header',
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        // ★ 关键：显式指定允许的算法，防御 Algorithm Confusion 攻击
        const { payload } = await jwtVerify(token, publicKey, {
            algorithms: ['RS256'],
            issuer: 'http://localhost:3000',
            audience: 'http://localhost:3000',
        });

        req.user = {
            id: parseInt(payload.sub),
            email: payload.email,
            role: payload.role,
        };
        next();
    } catch (err) {
        if (err.code === 'ERR_JWT_EXPIRED') {
            return res.status(401).json({ error: 'Access token expired', code: 'TOKEN_EXPIRED' });
        }
        return res.status(401).json({ error: 'Invalid access token' });
    }
};

// RBAC Middleware
const requireRole = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({
            error: 'Insufficient permissions',
            required: roles,
            current: req.user.role,
        });
    }
    next();
};

// ============================================
// 5. 路由
// ============================================

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// 登录 → 签发 Access Token + Refresh Token
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const dummyHash = '$2b$12$LJ3m4ys3Lk0TSwHjpF2gT.UzIR3WH9CPNRGK/7e7e3jY3CSJiXZ2e';
    const isMatch = await bcrypt.compare(password, user?.password_hash || dummyHash);

    if (!user || !isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    // 创建 Token Family（用于 Reuse Detection）
    const familyId = crypto.randomUUID();

    const accessToken = await generateAccessToken(user);
    const refreshToken = generateRefreshToken(user.id, familyId);

    console.log(`Login: ${email}, family: ${familyId}`);

    res.json({
        accessToken,
        refreshToken,
        expiresIn: 900, // 15 分钟 = 900 秒
        tokenType: 'Bearer',
    });
});

// Refresh → 新的 Access Token + 新的 Refresh Token（Rotation）
app.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
    }

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const stored = db.prepare(
        'SELECT * FROM refresh_tokens WHERE token_hash = ?'
    ).get(tokenHash);

    // Token 不存在
    if (!stored) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // ★ Reuse Detection：如果这个 Token 已经被使用过，说明它被盗了
    if (stored.is_used || stored.is_revoked) {
        // 吊销整个 Token Family！
        db.prepare(
            'UPDATE refresh_tokens SET is_revoked = 1 WHERE family_id = ?'
        ).run(stored.family_id);
        console.log(`⚠️ Reuse detected! Family ${stored.family_id} revoked`);
        return res.status(401).json({
            error: 'Refresh token reuse detected. All sessions in this family have been revoked.',
            code: 'TOKEN_REUSE',
        });
    }

    // Token 已过期
    if (new Date(stored.expires_at) < new Date()) {
        return res.status(401).json({ error: 'Refresh token expired' });
    }

    // 标记旧 Token 为已使用
    db.prepare('UPDATE refresh_tokens SET is_used = 1 WHERE id = ?').run(stored.id);

    // 获取用户信息
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(stored.user_id);

    // 签发新的 Token 对（同一个 Family）
    const newAccessToken = await generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user.id, stored.family_id);

    console.log(`Refresh: user ${user.email}, family ${stored.family_id}`);

    res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: 900,
        tokenType: 'Bearer',
    });
});

// 登出（吊销 Token Family）
app.post('/auth/logout', requireAuth, (req, res) => {
    const { refreshToken } = req.body;
    if (refreshToken) {
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
        const stored = db.prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get(tokenHash);
        if (stored) {
            db.prepare('UPDATE refresh_tokens SET is_revoked = 1 WHERE family_id = ?').run(stored.family_id);
            console.log(`Logout: family ${stored.family_id} revoked`);
        }
    }
    res.json({ message: 'Logged out successfully' });
});

// 受保护端点
app.get('/api/profile', requireAuth, (req, res) => {
    res.json({ user: req.user });
});

app.get('/api/notes', requireAuth, (req, res) => {
    res.json({
        notes: [
            { id: 1, title: 'JWT is stateless' },
            { id: 2, title: 'RS256 uses asymmetric keys' },
        ],
        user: req.user,
    });
});

// Admin-only 端点（RBAC）
app.get('/api/admin/users', requireAuth, requireRole('admin'), (req, res) => {
    const users = db.prepare('SELECT id, email, role FROM users').all();
    res.json({ users });
});

// Debug：解码 JWT（不验证签名）
app.post('/debug/decode', (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const parts = token.split('.');
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid JWT format' });

    try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

        res.json({
            header,
            payload,
            signature: parts[2].substring(0, 20) + '...',
            warning: 'This only decodes, it does NOT verify the signature!',
        });
    } catch {
        res.status(400).json({ error: 'Failed to decode JWT' });
    }
});

// ============================================
// 6. 启动
// ============================================
loadKeys()
    .then(() => initUsers())
    .then(() => {
        app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
    });