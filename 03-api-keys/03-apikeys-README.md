# Module 03 — API Keys

> 从"凭证型"认证迈向"无状态令牌型"认证的第一步——标识应用程序，而非用户。

---

## 学习目标

完成本 Module 后，你将能够：

- 理解 API Key 与 Basic Auth / Session Auth 的本质区别（标识应用 vs. 标识用户）
- 用密码学安全方法生成 API Key（Node.js `crypto` / Python `secrets`）
- 理解为什么数据库中要存储 API Key 的**哈希值**而不是明文
- 用 Node.js 从零实现 API Key Middleware + SQLite 存储
- 用 Python Flask + SQLite 实现同样的功能
- 实现 Per-Key Rate Limiting（每个 Key 独立的速率限制）
- 实现 API Key 的完整生命周期：生成、验证、用量追踪、吊销、轮换
- 理解 API Key 的安全最佳实践（Header 传递、哈希存储、定期轮换）
- 用 `curl` 和 `HTTPie` 从命令行测试 API Key 端点

---

## 前置准备

```bash
# 确保你在 repo 的 Module 03 目录
cd web-auth-learning/03-api-keys

# 创建子目录
mkdir -p node python tests
```

> **本 Module 不需要 Redis。** API Key 的验证是无状态的——每个请求携带 Key，服务端查数据库验证。不需要 Session Store。这正是 API Key 跟 Session Auth 的核心区别之一。

---

## Part 1：理论 — API Key 认证机制

### 这是什么？

API Key 是一个**长随机字符串**，用于标识**应用程序/开发者**而不是终端用户。Developer 注册后获得一个 API Key，在每个 API 请求中通过 Header 发送这个 Key，服务端验证 Key 的有效性并追踪用量。

你每天都在用 API Key——Google Maps API、OpenAI API、Stripe API、AWS Access Key——这些都是 API Key 模式。

### 三种认证方式的本质区别

| 维度 | Basic Auth (Module 01) | Session Auth (Module 02) | API Key (Module 03) |
|------|----------------------|-------------------------|---------------------|
| 标识的是 | 用户（人） | 用户（人） | **应用程序/开发者** |
| 状态 | 无状态 | **有状态**（服务端存 Session） | **无状态** |
| 凭证传输 | 每次请求（username:password） | 只在登录时 | 每次请求（API Key） |
| 需要 Session Store？ | 否 | **是**（Redis） | **否** |
| CSRF 风险？ | 否（不用 Cookie） | **是**（Cookie 自动发送） | **否**（不用 Cookie） |
| Logout？ | 无 | 有（销毁 Session） | 不需要（吊销 Key 即可） |

**关键认知：** API Key 回到了"每次请求都传凭证"的模式（跟 Basic Auth 类似），但有两个根本区别：

1. **传的不是用户密码**——而是一个独立生成的随机 Token，泄露后可以单独吊销，不影响用户密码
2. **标识的是应用**——同一个开发者可以有多个 API Key（开发环境、生产环境、不同项目），每个 Key 有独立的权限和用量限制

### API Key 的请求流程

```
CLIENT (Developer's App)                     SERVER
  |                                            |
  |  GET /api/weather?city=Toronto             |
  |  x-api-key: ak_live_7f3a9b2c...           |
  |  （API Key 在 Header 中，不在 URL 里！）     |
  |------------------------------------------->|
  |                                            |
  |  1) 提取 x-api-key Header                  |
  |  2) 哈希 Key → SHA-256                     |
  |  3) 在数据库中查找匹配的 hash               |
  |  4) 检查 Key 是否被吊销                     |
  |  5) 检查速率限制                             |
  |  6) 记录用量                                |
  |                                            |
  |  200 OK + 数据                              |
  |<-------------------------------------------|
```

### API Key 绝不要放在 URL Query Parameter 里

**错误：** `GET /api/data?api_key=ak_live_7f3a9b2c...`

为什么？因为 URL 会被记录到很多地方：

- Web 服务器的 access log（Nginx, Apache）
- 浏览器的历史记录
- 代理服务器的日志
- CDN 的日志
- 监控工具（如 New Relic, Datadog）
- 浏览器的 Referer Header（跳转到其他网站时会暴露）

**正确：** 通过 HTTP Header 传递

```
x-api-key: ak_live_7f3a9b2c...
```

或者用 `Authorization` Header：

```
Authorization: Bearer ak_live_7f3a9b2c...
```

两种都可以，`x-api-key` 更常见（因为 `Authorization: Bearer` 通常留给 JWT/OAuth Token）。

### API Key 的命名约定

好的 API Key 设计会在 Key 中包含元信息前缀，让人一眼就能识别：

```
ak_live_7f3a9b2c4d5e6f...   — 生产环境 Key
ak_test_1a2b3c4d5e6f7g...   — 测试环境 Key
sk_live_8h9i0j1k2l3m4n...   — Secret Key（服务端）
pk_live_5o6p7q8r9s0t1u...   — Public Key（客户端）
```

Stripe 就是这么做的——`sk_live_` 前缀让你在代码中一眼识别出这是一个 Stripe 的生产环境 Secret Key。GitHub 的 Personal Access Token 用 `ghp_` 前缀，这也是为什么 GitHub 能在公开代码中自动检测并吊销泄露的 Token（Secret Scanning）。

---

## Part 2：动手实践 — Node.js 实现

### Step 1：初始化项目

```bash
cd 03-api-keys/node
npm init -y
```

在 `package.json` 中添加 `"type": "module"`（本 Module 继续用 ES Modules）。

```bash
npm install express better-sqlite3 express-rate-limit
```
跟之前一样的 SSL 证书问题——better-sqlite3 需要下载预编译二进制文件或编译 C++ 代码，两步都因为 SSL 证书失败了。
之前 npm config set strict-ssl false 只对 npm registry 生效，但 node-gyp 和 prebuild-install 有自己的 HTTP 请求。全局关掉 SSL 验证 `export NODE_TLS_REJECT_UNAUTHORIZED=0`then do npm install ... again.

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `express` | 5.x / 4.x | Web 框架 |
| `better-sqlite3` | 12.x | SQLite 数据库（同步 API，比 node-sqlite3 更简洁） |
| `express-rate-limit` | 8.x | Per-IP / Per-Key 速率限制 |

> **为什么用 SQLite 而不是 Redis？** API Key 是持久化数据（注册、吊销、用量日志），需要一个真正的数据库。SQLite 对学习项目来说最简单——零配置，一个文件就是整个数据库。生产环境中你会用 PostgreSQL 或 DynamoDB。

### Step 2：实现完整的 API Key 系统

创建 `server.js`：

```javascript
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
```

### Step 3：运行并测试

```bash
node server.js
```

**完整测试流程：**

```bash
# ============================================
# 测试 1: 公开端点
# ============================================
curl http://localhost:3000/health
# 期望: {"status":"ok",...}

# ============================================
# 测试 2: 未提供 API Key
# ============================================
curl http://localhost:3000/api/weather
# 期望: 401 {"error":"API key required","hint":"Include your API key in the x-api-key header"}

# ============================================
# 测试 3: 注册获取 API Key
# ============================================
curl -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com","keyName":"my-weather-app"}' \
  http://localhost:3000/developer/register
# 期望: 201 {"message":"API key created successfully","apiKey":"ak_live_7f3a...","warning":"Save this key now!..."}
#
# ★ 复制返回的 apiKey 值！这是唯一一次能看到完整 Key

# ============================================
# 测试 4: 用 API Key 访问受保护端点
# ============================================
curl -H "x-api-key: <粘贴你的API Key>" \
  http://localhost:3000/api/weather?city=Toronto
# 期望: 200 {"city":"Toronto","temperature":"18°C",...}

# ============================================
# 测试 5: 使用无效的 API Key
# ============================================
curl -H "x-api-key: ak_live_invalid_key_here" \
  http://localhost:3000/api/weather
# 期望: 401 {"error":"Invalid or revoked API key"}

# ============================================
# 测试 6: 查看用量统计
# ============================================
curl -H "x-api-key: <你的API Key>" \
  http://localhost:3000/developer/usage
# 期望: {"keyPrefix":"ak_live_7f3a...","stats":{"total_requests":1,...},"recentRequests":[...]}

# ============================================
# 测试 7: 连续请求（观察 Rate Limit Header）
# ============================================
curl -v -H "x-api-key: <你的API Key>" \
  http://localhost:3000/api/weather
# 观察 Response Header:
# < RateLimit: limit=100, remaining=98, reset=3600
# 每次请求 remaining 减 1

# ============================================
# 测试 8: 轮换 API Key
# ============================================
curl -H "x-api-key: <你的API Key>" \
  -X POST http://localhost:3000/developer/rotate
# 期望: 201 {"message":"New API key generated...","newApiKey":"ak_live_..."}
# 旧 Key 仍然有效（grace period），新 Key 也能用

# ============================================
# 测试 9: 吊销 API Key
# ============================================
curl -H "x-api-key: <你的旧API Key>" \
  -X POST http://localhost:3000/developer/revoke
# 期望: {"message":"API key revoked successfully"}

# 验证旧 Key 已失效
curl -H "x-api-key: <你的旧API Key>" \
  http://localhost:3000/api/weather
# 期望: 401 {"error":"Invalid or revoked API key"}
```

### 在 SQLite 中检查 API Key 数据

```bash
sudo apt-get update && sudo apt-get install -y sqlite3
# 用 sqlite3 命令行工具查看数据库
sqlite3 03-api-keys/node/apikeys.db

# 查看所有注册的 API Key（注意：只能看到 hash，看不到明文！）
SELECT id, owner_email, key_prefix, name, is_active, created_at, revoked_at FROM api_keys;
# 输出: 1|dev@example.com|ak_live_7f3a9b2c|my-weather-app|1|2026-04-30 03:00:00|

# 查看用量日志
SELECT * FROM usage_logs ORDER BY timestamp DESC LIMIT 5;

# 查看每个 Key 的请求总数
SELECT k.key_prefix, k.owner_email, COUNT(u.id) as request_count
FROM api_keys k LEFT JOIN usage_logs u ON k.id = u.key_id
GROUP BY k.id;

# 退出
.quit
```

### 我们学到了什么？

- API Key 只在创建时返回一次（**跟 AWS Access Key 一样**）——服务端只存 hash，丢了就只能重新生成
- SHA-256 用于 API Key 哈希足够安全（因为 Key 本身就是高熵随机数），不需要 bcrypt 的慢速哈希
- Per-Key Rate Limiting 用 `express-rate-limit` 的 `keyGenerator` 实现——以 API Key hash 而不是 IP 作为限制的 key
- Key 轮换需要 grace period——新旧 Key 同时有效，给调用方时间更新

---

### Step 4：为什么 API Key 用 SHA-256 而不是 bcrypt？

这个问题很重要，因为 Module 01 和 02 中我们一直在用 bcrypt。

```
密码（低熵）:          "secret123"    → 可能只有 ~30 bits 熵
API Key（高熵）:       "ak_live_7f3a9b2c4d5e6f..." → 256 bits 熵

密码需要 bcrypt:
  攻击者拿到 hash 后，暴力破解 30 bits 的密码空间是可行的
  bcrypt 的慢速哈希（~250ms/次）大幅增加破解成本

API Key 用 SHA-256 就够了:
  攻击者拿到 hash 后，暴力破解 256 bits 的随机空间是不可能的
  即使每秒尝试 10 亿次，也需要 10^60 年
  SHA-256 快速哈希（微秒级）适合每个请求都要验证的场景
```

**总结：**

| 凭证类型 | 熵 | 哈希算法 | 原因 |
|---------|---|---------|------|
| 用户密码 | 低（人选择的） | bcrypt / Argon2id | 需要慢速哈希抵抗暴力破解 |
| API Key | 高（机器生成的） | SHA-256 | 高熵让暴力破解不可能，快速哈希适合高频验证 |

---

## Part 3：动手实践 — Python 实现

### Step 1：初始化项目

```bash
cd 03-api-keys/python

python3 --version
# 期望: Python 3.13.9

python3 -m venv venv
source venv/bin/activate
pip install Flask Flask-Limiter
```

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `Flask` | 3.x | Web 框架 |
| `Flask-Limiter` | 4.1.1 | Rate Limiting（装饰器模式） |

> **Python 不需要安装 SQLite 包**——`sqlite3` 是 Python 标准库的一部分，直接 `import sqlite3` 就能用。

### Step 2：实现完整的 API Key 系统

创建 `app.py`

### Step 3：运行并测试

```bash
python app.py
```

测试命令跟 Node.js 版本完全一样——把端口改成 `5001`：

```bash
# 注册
curl -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com","keyName":"my-weather-app"}' \
  http://localhost:5001/developer/register

# 使用
curl -H "x-api-key: <你的API Key>" \
  http://localhost:5001/api/weather?city=Toronto

# 用量
curl -H "x-api-key: <你的API Key>" \
  http://localhost:5001/developer/usage

# 轮换
curl -H "x-api-key: <你的API Key>" \
  -X POST http://localhost:5001/developer/rotate

# 吊销
curl -H "x-api-key: <你的API Key>" \
  -X POST http://localhost:5001/developer/revoke
```

### 我们学到了什么？

- Python `secrets.token_hex(32)` 等同于 Node.js `crypto.randomBytes(32).toString('hex')`——都是 CSPRNG
- Python `hashlib.sha256()` 等同于 Node.js `crypto.createHash('sha256')`
- Flask-Limiter 的装饰器模式 `@limiter.limit('100 per hour')` 比 Express 的 Middleware 模式更简洁
- Flask 的 `g` 对象是请求级别的全局变量——类似 Express 中把数据挂到 `req` 上

---

## Part 4：安全最佳实践

### 1. 生成：必须用 CSPRNG

```javascript
// Node.js — ✅ 正确
crypto.randomBytes(32).toString('hex')

// Node.js — ❌ 错误（Math.random 不是密码学安全的）
Math.random().toString(36).substring(2)
```

```python
# Python — ✅ 正确
secrets.token_hex(32)
secrets.token_urlsafe(32)

# Python — ❌ 错误（random 模块不是密码学安全的）
import random
''.join(random.choices('abcdef0123456789', k=64))
```

OWASP 建议 API Key 至少 **32 字符**（256 bits），64 字符更好。我们的实现是 `ak_live_` + 64 hex = 72 字符。

### 2. 存储：数据库中只存哈希

跟 Module 01 存密码的原则一样——如果数据库泄露，攻击者拿到的只是 hash，无法还原原始 Key。

```
数据库内容:
| key_prefix      | key_hash                                                         |
|-----------------|------------------------------------------------------------------|
| ak_live_7f3a9b2c| a1b2c3d4e5f6...（SHA-256 hash，64 hex chars）                     |
```

攻击者拿到 hash 后，要暴力破解 256 bits 的随机空间——不可能。

### 3. 传递：只用 Header，不用 URL

```bash
# ✅ 正确
curl -H "x-api-key: ak_live_..." http://api.example.com/data

# ❌ 错误（Key 会出现在日志、Referer、浏览器历史中）
curl "http://api.example.com/data?api_key=ak_live_..."
```

### 4. 轮换：定期更换，支持 Grace Period

NIST SP 800-53 建议每 **90 天**轮换一次。轮换期间新旧 Key 同时有效（grace period），给调用方时间更新。

```
Day 0:   生成新 Key B
Day 0-7: Key A 和 Key B 都有效（grace period）
Day 7:   吊销 Key A
```

这跟 AWS IAM Access Key 轮换的最佳实践完全一样——先创建新 Key，更新所有使用旧 Key 的地方，确认无误后再删除旧 Key。

### 5. 速率限制：Per-Key，不只是 Per-IP

Per-IP Rate Limiting 不够——同一个 IP 后面可能有多个 Developer（共享 VPN/NAT），不同 Developer 应该有独立的配额。

```javascript
// ✅ 以 API Key 为单位限制
keyGenerator: (req) => hashApiKey(req.headers['x-api-key'])

// ❌ 只以 IP 为单位限制
keyGenerator: (req) => req.ip
```

---

## Part 5：测试工具速查

### curl 命令

```bash
# 注册获取 API Key
curl -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com"}' \
  http://localhost:3000/developer/register

# 用 API Key 访问端点
curl -H "x-api-key: ak_live_..." \
  http://localhost:3000/api/weather?city=Toronto

# 详细模式（观察 RateLimit Header）
curl -v -H "x-api-key: ak_live_..." \
  http://localhost:3000/api/weather

# 查看用量
curl -H "x-api-key: ak_live_..." \
  http://localhost:3000/developer/usage

# 轮换
curl -H "x-api-key: ak_live_..." \
  -X POST http://localhost:3000/developer/rotate

# 吊销
curl -H "x-api-key: ak_live_..." \
  -X POST http://localhost:3000/developer/revoke
```

### HTTPie 命令

```bash
# 注册
http POST :3000/developer/register email=dev@example.com keyName=my-app

# 用 API Key 访问
http :3000/api/weather city==Toronto x-api-key:ak_live_...

# 详细模式
http -v :3000/api/weather x-api-key:ak_live_...

# 用量
http :3000/developer/usage x-api-key:ak_live_...

# 轮换
http POST :3000/developer/rotate x-api-key:ak_live_...

# 吊销
http POST :3000/developer/revoke x-api-key:ak_live_...
```

### SQLite 命令

```bash
sqlite3 apikeys.db

# 查看所有 Key
SELECT id, owner_email, key_prefix, name, is_active FROM api_keys;

# 查看用量日志
SELECT * FROM usage_logs ORDER BY timestamp DESC LIMIT 10;

# 按 Key 统计请求数
SELECT k.key_prefix, COUNT(u.id) as requests
FROM api_keys k LEFT JOIN usage_logs u ON k.id = u.key_id
GROUP BY k.id;

.quit
```

---

## Part 6：Node.js 与 Python 实现对比

| 维度 | Node.js | Python |
|------|---------|--------|
| 随机数生成 | `crypto.randomBytes(32).toString('hex')` | `secrets.token_hex(32)` |
| SHA-256 哈希 | `crypto.createHash('sha256').update(key).digest('hex')` | `hashlib.sha256(key.encode()).hexdigest()` |
| SQLite | `better-sqlite3`（同步 API） | `sqlite3`（标准库） |
| Rate Limiting | `express-rate-limit`（Middleware） | `Flask-Limiter`（装饰器） |
| 请求级变量 | `req.apiKey = ...` | `g.api_key = ...` |
| Key 验证模式 | Middleware 函数 | 装饰器 `@require_api_key` |

---

## Part 7：适用场景与局限性

### API Key 适用于

- **Developer API / Public API** — 给第三方开发者使用的 API（OpenAI, Google Maps, Stripe）
- **服务间通信（M2M）** — 微服务之间的认证（不涉及用户交互）
- **用量追踪和计费** — 按 Key 统计 API 调用次数，生成用量报表
- **访问控制和速率限制** — 不同 tier 的 Key 有不同的配额
- **CI/CD Pipeline 认证** — 部署脚本、GitHub Actions 调用 API

### API Key 不适用于

- **标识终端用户** — API Key 标识的是应用/开发者，不是用户。如果你需要知道"是哪个用户在操作"，用 Session Auth 或 JWT
- **需要细粒度权限控制** — API Key 通常是全有或全无。如果需要"这个 Token 只能读取用户 A 的数据"，用 OAuth 2.0 (Module 05)
- **需要短生命周期** — API Key 通常长期有效（90 天），如果需要 5-15 分钟过期的 Token，用 JWT (Module 04)

### 从 Session Auth 到 API Key 解决了什么？

| Session Auth 的局限 | API Key 怎么解决的 |
|---|---|
| 有状态（需要 Redis） | 无状态（每个请求独立验证） |
| 依赖 Cookie（浏览器特性） | 通过 Header 传递（任何 HTTP 客户端都能用） |
| CSRF 风险 | 不用 Cookie，没有 CSRF 问题 |
| 难以做 M2M 认证 | 天然适合服务间通信 |

### API Key 引入了什么新问题？

| 新问题 | 后续 Module 怎么解决 |
|---|---|
| 没有用户身份信息 | Module 04: JWT（Token 中包含用户 Claims） |
| 没有过期机制（除了手动吊销） | Module 04: JWT（内置 `exp` 过期时间） |
| 没有权限范围（Scope） | Module 05: OAuth 2.0（Scope 机制） |
| Key 泄露后需要手动轮换 | Module 04: Access + Refresh Token Rotation |

---

## Part 8：模块总结与自查清单

### 安全清单

- [ ] API Key 使用 CSPRNG 生成（`crypto.randomBytes` / `secrets.token_hex`）
- [ ] 数据库存储 **SHA-256 哈希值**，不存明文
- [ ] API Key 只通过 **Header** 传递，不放在 URL Query Parameter 中
- [ ] 实现 **Per-Key Rate Limiting**（不只是 Per-IP）
- [ ] API Key 只在创建时返回一次
- [ ] 支持 **Key 吊销**（revocation）
- [ ] 支持 **Key 轮换**（rotation with grace period）
- [ ] 记录每个 Key 的 **用量日志**
- [ ] Key 使用有意义的 **前缀**（`ak_live_`, `ak_test_`）

### 概念自查

- [ ] 我能解释 API Key 和 Session Auth 的本质区别（标识应用 vs. 标识用户，无状态 vs. 有状态）
- [ ] 我能解释为什么 API Key 用 SHA-256 而不是 bcrypt（高熵 vs. 低熵）
- [ ] 我能解释为什么 API Key 不能放在 URL 中（日志、Referer、浏览器历史等风险）
- [ ] 我能解释 Key 轮换中 grace period 的作用
- [ ] 我能用 `crypto.randomBytes` / `secrets.token_hex` 生成安全的随机 Token
- [ ] 我知道 API Key 适合和不适合的使用场景
- [ ] 我理解 Per-Key Rate Limiting 和 Per-IP Rate Limiting 的区别

---

## 下一步

完成本 Module 后，进入 [Module 04 — JWT 与 Access/Refresh Token](../04-jwt-auth/README.md)。

JWT 是无状态认证的终极形态——Token 自身就包含所有验证信息：

1. **自包含（Self-contained）** — Token 的 Payload 中直接携带用户信息和权限声明（Claims），服务端不需要查数据库
2. **内置过期机制** — `exp` Claim 让 Token 自动过期，不需要手动吊销
3. **可签名验证** — 任何拥有公钥的服务都能独立验证 Token 的真实性，非常适合微服务架构

---

## 参考资料

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST SP 800-53 — Security and Privacy Controls](https://csf.tools/reference/nist-sp-800-53/)
- [express-rate-limit Documentation](https://express-rate-limit.mintlify.app/)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [better-sqlite3 GitHub](https://github.com/WiseLibs/better-sqlite3)
- [Stripe API Key Prefixes](https://docs.stripe.com/keys) — 业界最佳实践参考
