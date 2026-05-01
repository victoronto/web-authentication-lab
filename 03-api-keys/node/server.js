// server.js — 完整的 API Key 认证系统
import express from 'express';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());
const PORT = 3000;

// ============================================
// 1. 初始化 SQLite 数据库
// ============================================
const db = new Database('apikeys.db');
db.pragma('journal_mode = WAL'); // 性能优化

// 创建表
db.exec(`
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
`);

// ============================================
// 2. API Key 生成与哈希
// ============================================

/**
 * 生成一个密码学安全的 API Key
 * 格式: ak_live_<32字节随机hex>
 * 总长度: 8 (前缀) + 64 (hex) = 72 字符
 */
function generateApiKey() {
    const randomPart = crypto.randomBytes(32).toString('hex');
    return `ak_live_${randomPart}`;
}

/**
 * 对 API Key 做 SHA-256 哈希
 *
 * 为什么用 SHA-256 而不是 bcrypt？
 * - API Key 本身已经是 32 字节的随机数（256 bits 熵）
 * - bcrypt 是为低熵密码设计的（人类选择的密码，通常 20-40 bits 熵）
 * - 对高熵的随机 Token，SHA-256 就够了——暴力破解 256 bits 是不可能的
 * - SHA-256 比 bcrypt 快很多，适合每个请求都要验证的场景
 */
function hashApiKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * 提取 Key 的前缀（用于日志和查找，不泄露完整 Key）
 * ak_live_7f3a9b2c4d5e6f... → ak_live_7f3a9b2c
 */
function getKeyPrefix(key) {
    return key.substring(0, 16);
}

// ============================================
// 3. API Key 验证 Middleware
// ============================================
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({
            error: 'API key required',
            hint: 'Include your API key in the x-api-key header',
        });
    }

    // 哈希后查找（数据库里只存 hash，不存明文）
    const keyHash = hashApiKey(apiKey);
    const keyRecord = db.prepare(
        'SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1 AND revoked_at IS NULL'
    ).get(keyHash);

    if (!keyRecord) {
        return res.status(401).json({ error: 'Invalid or revoked API key' });
    }

    // 把 Key 信息挂到 req 上，供后续 Middleware 和路由使用
    req.apiKey = keyRecord;
    next();
};

// ============================================
// 4. 用量记录 Middleware
// ============================================
const logUsage = (req, res, next) => {
    // 在响应完成后记录用量
    res.on('finish', () => {
        if (req.apiKey) {
            db.prepare(
                'INSERT INTO usage_logs (key_id, endpoint, method, status_code) VALUES (?, ?, ?, ?)'
            ).run(req.apiKey.id, req.path, req.method, res.statusCode);
        }
    });
    next();
};

// ============================================
// 5. Per-Key Rate Limiting
// ============================================
const apiKeyRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 小时
    limit: 100,                // 每个 Key 100 次/小时
    standardHeaders: 'draft-8', // 返回标准 RateLimit Header
    legacyHeaders: false,
    // 用 API Key 的 hash 作为限制的 key（而不是 IP）
    keyGenerator: (req) => {
        return req.headers['x-api-key']
            ? hashApiKey(req.headers['x-api-key'])
            : req.ip;
    },
    message: {
        error: 'Rate limit exceeded',
        retryAfter: 'Check the RateLimit-Reset header',
    },
});

// ============================================
// 6. 路由 — 公开端点
// ============================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// 7. 路由 — Developer 注册（获取 API Key）
// ============================================
app.post('/developer/register', (req, res) => {
    const { email, keyName } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }

    // 生成 API Key
    const apiKey = generateApiKey();
    const keyHash = hashApiKey(apiKey);
    const keyPrefix = getKeyPrefix(apiKey);

    // 存储哈希值（不存明文！）
    db.prepare(
        'INSERT INTO api_keys (owner_email, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)'
    ).run(email, keyPrefix, keyHash, keyName || 'default');

    console.log(`New API Key registered for ${email}: ${keyPrefix}...`);

    // ★ 关键：API Key 只在创建时返回给用户一次
    // 之后无法从数据库中恢复（因为只存了 hash）
    // 告诉用户务必保存好
    res.status(201).json({
        message: 'API key created successfully',
        apiKey: apiKey,
        prefix: keyPrefix,
        warning: 'Save this key now! It cannot be retrieved later.',
    });
});

// ============================================
// 8. 路由 — 受保护的 API 端点
// ============================================

app.get('/api/weather',
    apiKeyRateLimit,
    validateApiKey,
    logUsage,
    (req, res) => {
        const city = req.query.city || 'Toronto';
        res.json({
            city,
            temperature: '18°C',
            condition: 'Partly Cloudy',
            requestedBy: req.apiKey.owner_email,
            keyPrefix: req.apiKey.key_prefix,
        });
    }
);

app.get('/api/forecast',
    apiKeyRateLimit,
    validateApiKey,
    logUsage,
    (req, res) => {
        res.json({
            forecast: [
                { day: 'Monday', high: '20°C', low: '12°C' },
                { day: 'Tuesday', high: '22°C', low: '14°C' },
                { day: 'Wednesday', high: '19°C', low: '11°C' },
            ],
            requestedBy: req.apiKey.owner_email,
        });
    }
);

// ============================================
// 9. 路由 — Key 管理
// ============================================

// 查看用量统计
app.get('/developer/usage',
    validateApiKey,
    (req, res) => {
        const stats = db.prepare(`
      SELECT
        COUNT(*) as total_requests,
        MIN(timestamp) as first_request,
        MAX(timestamp) as last_request
      FROM usage_logs
      WHERE key_id = ?
    `).get(req.apiKey.id);

        const recentRequests = db.prepare(`
      SELECT endpoint, method, status_code, timestamp
      FROM usage_logs
      WHERE key_id = ?
      ORDER BY timestamp DESC
      LIMIT 10
    `).all(req.apiKey.id);

        res.json({
            keyPrefix: req.apiKey.key_prefix,
            keyName: req.apiKey.name,
            stats,
            recentRequests,
        });
    }
);

// 吊销 API Key
app.post('/developer/revoke',
    validateApiKey,
    (req, res) => {
        db.prepare(
            "UPDATE api_keys SET is_active = 0, revoked_at = datetime('now') WHERE id = ?"
        ).run(req.apiKey.id);

        console.log(`API Key revoked: ${req.apiKey.key_prefix}...`);
        res.json({
            message: 'API key revoked successfully',
            prefix: req.apiKey.key_prefix,
        });
    }
);

// 轮换 API Key（生成新 Key，旧 Key 保留一段时间）
app.post('/developer/rotate',
    validateApiKey,
    (req, res) => {
        const oldPrefix = req.apiKey.key_prefix;

        // 生成新 Key
        const newApiKey = generateApiKey();
        const newKeyHash = hashApiKey(newApiKey);
        const newKeyPrefix = getKeyPrefix(newApiKey);

        // 存储新 Key
        db.prepare(
            'INSERT INTO api_keys (owner_email, key_prefix, key_hash, name) VALUES (?, ?, ?, ?)'
        ).run(req.apiKey.owner_email, newKeyPrefix, newKeyHash, `${req.apiKey.name} (rotated)`);

        // 旧 Key 暂时保留（给调用方一个过渡期），标记为即将过期
        // 生产环境中你可以设一个 grace period（比如 24 小时后自动吊销）
        console.log(`API Key rotated: ${oldPrefix}... → ${newKeyPrefix}...`);

        res.status(201).json({
            message: 'New API key generated. Old key is still active for a grace period.',
            newApiKey: newApiKey,
            newPrefix: newKeyPrefix,
            oldPrefix: oldPrefix,
            warning: 'Save the new key now! Update your application to use it, then revoke the old key.',
        });
    }
);

// ============================================
// 10. 启动服务器
// ============================================
app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));