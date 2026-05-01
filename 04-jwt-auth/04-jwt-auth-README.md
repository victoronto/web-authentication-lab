# Module 04 — JWT 与 Access/Refresh Token

> 无状态认证的终极形态——Token 自身就包含所有验证信息，任何服务都能独立验证。

---

## 学习目标

完成本 Module 后，你将能够：

- 理解 JWT 的三段式结构（Header.Payload.Signature）并能手动解码
- 解释对称签名（HS256）和非对称签名（RS256 / ES256）的区别及使用场景
- 理解并防御 Algorithm Confusion 攻击（2026 年仍有活跃 CVE）
- 用 Node.js (`jose`) 从零实现 JWT 签发与验证
- 用 Python (`PyJWT`) 实现同样的功能
- 实现 Access Token + Refresh Token 双 Token 模式
- 实现 Refresh Token Rotation 和 Reuse Detection（Token Family 吊销）
- 通过 JWT Claims 实现 RBAC（Role-Based Access Control）
- 用 `curl`、`jwt.io` 和命令行工具调试 JWT
- 理解 JWT 相比 Session Auth 和 API Key 的优劣势

---

## 前置准备

```bash
# 确保你在 repo 的 Module 04 目录
cd web-auth-learning/04-jwt-auth

mkdir -p node python tests
```

---

## Part 1：理论 — JWT 是什么？

### 核心概念

JSON Web Token（JWT，读作 "jot"）定义于 **RFC 7519**。它是一个紧凑的、URL 安全的字符串，由三部分组成，用 `.` 连接：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcxNDQ4MDAwMCwiZXhwIjoxNzE0NDgwOTAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 ↑ Header              ↑ Payload                                                                                          ↑ Signature
```

**每一段都是 Base64URL 编码的：**

```
Header（头部）:
{
  "alg": "HS256",     ← 签名算法
  "typ": "JWT"        ← Token 类型
}

Payload（负载 / Claims）:
{
  "sub": "1",                        ← Subject（用户 ID）
  "email": "admin@example.com",      ← 自定义 Claim
  "role": "admin",                   ← 自定义 Claim
  "iat": 1714480000,                 ← Issued At（签发时间）
  "exp": 1714480900                  ← Expiration（过期时间）
}

Signature（签名）:
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### 跟之前所有认证方式的对比

| 维度 | Basic Auth | Session Auth | API Key | **JWT** |
|------|-----------|-------------|---------|---------|
| 状态 | 无状态 | 有状态 | 无状态 | **无状态** |
| 包含用户信息？ | 否（只有凭证） | 否（Session ID 是随机数） | 否（Key 是随机数） | **是（Claims 在 Payload 里）** |
| 过期机制 | 无 | 服务端控制 TTL | 手动吊销 | **内置 `exp` Claim** |
| 服务端存储 | 无 | Redis/数据库 | 数据库（Key hash） | **无（签名验证即可）** |
| 适合微服务？ | 否 | 差（需要共享 Redis） | 一般 | **最适合** |

**JWT 的本质：** 一个**经过签名的 JSON 对象**。服务端签发时用密钥签名，验证时用密钥检查签名——如果签名有效，说明 Payload 没被篡改，可以信任其中的信息。**不需要查数据库。**

这就是为什么 JWT 特别适合微服务——每个微服务只需要拥有验证密钥（公钥），就能独立验证 Token，不需要连接同一个 Redis 或数据库。

### Base64URL 编码不是加密！

跟 Module 01 的 Basic Auth 一样——**Base64 是编码，不是加密**。JWT 的 Payload 任何人都能解码。

```bash
# 拿到一个 JWT 后，直接解码 Payload：
echo "eyJzdWIiOiIxIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSJ9" | base64 -d
# 输出: {"sub":"1","email":"admin@example.com"}
```

**所以绝不要在 JWT Payload 中放敏感信息**——密码、信用卡号、SSN 等。任何拿到 Token 的人都能读取 Payload。Signature 只保证数据**没被篡改**，不保证数据**保密**。

### 签名算法：对称 vs. 非对称

| 算法 | 类型 | 签名密钥 | 验证密钥 | 适用场景 |
|------|------|---------|---------|---------|
| **HS256** | 对称（HMAC） | 共享 Secret | **同一个** Secret | 单体应用、快速原型 |
| **RS256** | 非对称（RSA） | Private Key | **Public Key** | 微服务、多方验证 |
| **ES256** | 非对称（ECDSA） | Private Key | **Public Key** | 同 RS256，但 Key 更短、签名更小 |

**为什么微服务要用非对称算法？**

```
HS256（对称）:
  Auth Service 和 API Service 必须共享同一个 secret
  → 任何拥有 secret 的服务都能签发 Token
  → 一个服务被攻破 = 所有服务被攻破

RS256/ES256（非对称）:
  Auth Service 持有 Private Key（能签发 Token）
  API Service 只有 Public Key（只能验证 Token，不能签发）
  → API Service 被攻破，攻击者只拿到 Public Key，无法伪造 Token
```

---

### Algorithm Confusion 攻击（2026 年仍有活跃 CVE！）

这是 JWT 最重要的安全漏洞之一——**2026 年 1 月还有两个新 CVE**（Hono 框架 CVSS 8.2，HarbourJwt）。

**攻击原理：**

1. 服务端配置了 RS256（非对称）——用 Private Key 签名，用 Public Key 验证
2. 攻击者从 `/.well-known/jwks.json` 获取 Public Key（这是公开的）
3. 攻击者创建一个 JWT，把 Header 的 `alg` 改成 `HS256`
4. 攻击者用 Public Key 作为 HMAC Secret 签名这个 JWT
5. **漏洞库**读取 Token Header 中的 `alg: HS256`，用 Public Key 做 HMAC 验证——验证通过！

**防御：永远 whitelist 允许的算法，不要信任 Token Header 中的 `alg`。**

```javascript
// Node.js (jose)
await jwtVerify(token, publicKey, { algorithms: ['RS256'] });

// Python (PyJWT)
jwt.decode(token, public_key, algorithms=['RS256'])
```

这是一条**必须记住的铁律**：每个 `verify()` 调用都要显式指定允许的算法列表。

---

### Access Token + Refresh Token 模式

JWT 的一个核心问题：**一旦签发就无法撤销**（在 `exp` 到期前）。没有服务端状态就意味着没有地方"删除"一个 Token。

解决方案是**双 Token 模式**：

| Token | 生命周期 | 存储位置 | 用途 |
|-------|---------|---------|------|
| **Access Token** | 短（5-15 分钟） | JavaScript 内存（SPA）/ Header | 访问受保护资源 |
| **Refresh Token** | 长（7-30 天） | `HttpOnly` Cookie / 数据库 | 获取新的 Access Token |

**为什么 Access Token 要这么短？**

因为它无法撤销。即使用户被禁用、密码被修改，已经签发的 Access Token 在过期前仍然有效。5-15 分钟的生命周期限制了这个风险窗口。

**Refresh Token Rotation 流程：**

```
CLIENT                          AUTH SERVER                    DATABASE
  |                                 |                             |
  |  1) POST /token/refresh         |                             |
  |  Refresh Token: RT-1            |                             |
  |-------------------------------->|                             |
  |                                 |  2) 查找 RT-1               |
  |                                 |  → 有效，属于 Token Family F1|
  |                                 |                             |
  |                                 |  3) 签发新 Access Token      |
  |                                 |  4) 签发新 Refresh Token RT-2|
  |                                 |  5) 吊销 RT-1（标记为已使用） |
  |                                 |                             |
  |  6) 返回: AT-new + RT-2         |                             |
  |<--------------------------------|                             |
  |                                 |                             |
  |  下次刷新用 RT-2，不能再用 RT-1   |                             |
```

**Reuse Detection（Token Family 吊销）：**

如果已经被吊销的 RT-1 再次被使用（说明 RT-1 被盗了），整个 Token Family 必须全部吊销——所有关联的 Refresh Token 全部失效，强制用户重新登录。

---

## Part 2：动手实践 — Node.js 实现

### Step 1：初始化项目

```bash
cd 04-jwt-auth/node
npm init -y
```

在 `package.json` 中添加 `"type": "module"`。

```bash
npm install express jose better-sqlite3
```

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `jose` | 6.2.3 | JWT 签发与验证（零依赖，跨运行时）— **2026 年 Node.js JWT 首选** |
| `better-sqlite3` | 12.x | 存储 Refresh Token 和 Token Family |

> **为什么用 `jose` 而不是 `jsonwebtoken`？** `jsonwebtoken`（9.x）是老牌库，教程最多。但 `jose` 是 OAuth/OIDC 标准作者维护的，零依赖，支持 Web Crypto API，可以在 Node.js、Deno、Bun、Cloudflare Workers、浏览器中运行。`jsonwebtoken` 只支持 Node.js。新项目推荐 `jose`。

### Step 2：生成 RSA 密钥对

```bash
# 在 04-jwt-auth/node 目录下生成密钥对
# 生产环境应该用 KMS（AWS KMS、HashiCorp Vault）管理密钥
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

> 你现在有两个文件：`private.pem`（Auth Server 签发 Token 用）和 `public.pem`（API Server 验证 Token 用）。**永远不要把 `private.pem` 提交到 Git。** 加到 `.gitignore` 里。

### Step 3：实现完整的 JWT 认证系统

创建 `server.js`：

```javascript
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
```

### Step 4：运行并测试

```bash
# 先生成密钥（如果还没生成）
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

npm install bcrypt  # 如果之前没装
node server.js
```

```bash
# ============================================
# 测试 1: 登录获取 Token 对
# ============================================
curl -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/auth/login
# 期望: {"accessToken":"eyJ...","refreshToken":"a1b2c3...","expiresIn":900,"tokenType":"Bearer"}
# 保存两个 Token！

# ============================================
# 测试 2: 用 Access Token 访问受保护端点
# ============================================
curl -H "Authorization: Bearer <粘贴accessToken>" \
  http://localhost:3000/api/profile
# 期望: {"user":{"id":1,"email":"admin@example.com","role":"admin"}}
# 注意：用 Authorization: Bearer，不是 x-api-key！

# ============================================
# 测试 3: 解码 JWT（看看里面有什么）
# ============================================
curl -H "Content-Type: application/json" \
  -d '{"token":"<粘贴accessToken>"}' \
  http://localhost:3000/debug/decode
# 期望: { header: { alg:"RS256" }, payload: { sub:"1", email:"...", exp:... } }

# ============================================
# 测试 4: 命令行手动解码 JWT
# ============================================
# 把 JWT 按 . 分割，解码第二段（Payload）
echo "<JWT的第二段>" | base64 -d
# 输出: {"sub":"1","email":"admin@example.com","role":"admin","iat":...,"exp":...}
# 任何人都能做到这一步！Payload 不是加密的！

# ============================================
# 测试 5: RBAC — Admin 端点
# ============================================
# 用 admin 的 Token
curl -H "Authorization: Bearer <admin的accessToken>" \
  http://localhost:3000/api/admin/users
# 期望: 200 {"users":[...]}

# 用 viewer 的 Token（先登录 viewer）
curl -H "Content-Type: application/json" \
  -d '{"email":"viewer@example.com","password":"readonly456"}' \
  http://localhost:3000/auth/login
# 拿到 viewer 的 accessToken

curl -H "Authorization: Bearer <viewer的accessToken>" \
  http://localhost:3000/api/admin/users
# 期望: 403 {"error":"Insufficient permissions","required":["admin"],"current":"viewer"}

# ============================================
# 测试 6: Refresh Token Rotation
# ============================================
curl -H "Content-Type: application/json" \
  -d '{"refreshToken":"<粘贴refreshToken>"}' \
  http://localhost:3000/auth/refresh
# 期望: {"accessToken":"<新的AT>","refreshToken":"<新的RT>","expiresIn":900}
# 旧的 Refresh Token 已被标记为已使用

# ============================================
# 测试 7: Reuse Detection（用旧的 Refresh Token 再刷新）
# ============================================
curl -H "Content-Type: application/json" \
  -d '{"refreshToken":"<旧的refreshToken，测试6之前的>"}' \
  http://localhost:3000/auth/refresh
# 期望: 401 {"error":"Refresh token reuse detected...","code":"TOKEN_REUSE"}
# 整个 Token Family 被吊销！

# ============================================
# 测试 8: 等 Access Token 过期（15 分钟后）
# ============================================
# 过期后再用：
curl -H "Authorization: Bearer <过期的accessToken>" \
  http://localhost:3000/api/profile
# 期望: 401 {"error":"Access token expired","code":"TOKEN_EXPIRED"}
# 这时需要用 Refresh Token 获取新的 Access Token
```

### 在 jwt.io 上检查 Token

打开 [jwt.io](https://jwt.io)，把你的 Access Token 粘贴进去：

- 左侧会显示解码后的 Header 和 Payload
- 右侧可以粘贴 Public Key（`public.pem` 的内容）来验证签名
- 签名有效时会显示 "Signature Verified"

### 我们学到了什么？

- `jose` 的 API：`new SignJWT(payload).setProtectedHeader().setExpirationTime().sign(key)` 签发，`jwtVerify(token, key, { algorithms })` 验证
- Access Token 是 JWT（自包含、无状态），Refresh Token 是普通随机字符串（有状态、存数据库）
- Reuse Detection 通过 Token Family 实现——一旦检测到旧 Token 被重用，整个 Family 吊销
- RBAC 通过 JWT Payload 中的 `role` Claim 实现，用 Middleware 检查

---

## Part 3：动手实践 — Python 实现

### Step 1：初始化项目

```bash
cd 04-jwt-auth/python

python3 -m venv venv
source venv/bin/activate
pip install Flask PyJWT cryptography
```

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `PyJWT` | 2.12.1 | JWT 签发与验证 — **2026 年 Python JWT 首选** |
| `cryptography` | — | PyJWT 的 RS256 需要这个依赖 |

> **`python-jose` 已废弃！** 自 2021 年起不再维护，在 Python ≥ 3.10 上会报 `ImportError`。FastAPI 的文档已经迁移回 PyJWT。如果你需要完整的 JOSE 套件（JWE、JWK），可以用 `joserfc`（Authlib 作者开发）。

### Step 2：复用密钥对

```bash
# 复制 Node.js 生成的密钥（或重新生成）
cp ../node/private.pem .
cp ../node/public.pem .
```

### Step 3：实现完整的 JWT 认证系统

创建 `app.py`：

```python
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
```

### Step 4：运行并测试

```bash
python app.py
```

测试命令跟 Node.js 版本相同，端口改为 `5001`。

---

## Part 4：安全要点总结

### 1. 永远 Whitelist 算法

```javascript
// Node.js — jose
await jwtVerify(token, key, { algorithms: ['RS256'] }); // ✅

// Python — PyJWT
jwt.decode(token, key, algorithms=['RS256'])              // ✅
jwt.decode(token, key)                                    // ❌ 危险！
```

### 2. JWT Payload 不放敏感信息

Payload 是 Base64 编码的，任何人都能解码。只放标识信息（`sub`, `email`, `role`），不放密码、信用卡号等。

### 3. Access Token 短、Refresh Token 长

Access Token ≤ 15 分钟。Refresh Token 7-30 天，存在服务端数据库（有状态），支持吊销。

### 4. Refresh Token 不是 JWT

Refresh Token 用普通随机字符串 + SHA-256 存储。因为它需要能被吊销（有状态），用 JWT 做 Refresh Token 就失去了服务端控制的能力。

### 5. 生产环境用非对称算法

RS256 或 ES256。Auth Server 持有 Private Key 签发 Token，其他服务只有 Public Key 验证 Token。

---

## Part 5：测试工具速查

### curl 命令

```bash
# 登录
curl -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/auth/login

# 用 Access Token 访问
curl -H "Authorization: Bearer <accessToken>" \
  http://localhost:3000/api/profile

# Refresh Token
curl -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}' \
  http://localhost:3000/auth/refresh

# 手动解码 JWT Payload
echo "<JWT第二段>" | base64 -d
```

### HTTPie 命令

```bash
# 登录
http POST :3000/auth/login email=admin@example.com password=secret123

# 用 Access Token 访问
http :3000/api/profile Authorization:"Bearer <accessToken>"

# Refresh
http POST :3000/auth/refresh refreshToken="<refreshToken>"
```

### jwt.io

打开 [jwt.io](https://jwt.io)，粘贴 JWT，左侧查看 Header/Payload，右侧粘贴 Public Key 验证签名。

---

## Part 6：Node.js 与 Python 实现对比

| 维度 | Node.js | Python |
|------|---------|--------|
| JWT 库 | `jose` v6.2.3 | `PyJWT` v2.12.1 |
| 签发 | `new SignJWT(payload).sign(key)` | `jwt.encode(payload, key, algorithm='RS256')` |
| 验证 | `jwtVerify(token, key, { algorithms })` | `jwt.decode(token, key, algorithms=['RS256'])` |
| 密钥导入 | `importPKCS8()` / `importSPKI()` | 直接传 PEM 字符串 |
| Refresh Token 存储 | `better-sqlite3` | `sqlite3`（标准库） |

---

## Part 7：适用场景与局限性

### JWT 适用于

- **微服务架构** — 每个服务独立验证 Token，不需要共享 Session Store
- **跨域 API** — Token 通过 `Authorization` Header 传递，没有 Cookie 的 SameSite/Domain 限制
- **移动端 / SPA** — 不依赖浏览器 Cookie 机制
- **短生命周期的授权凭证** — Access Token 自动过期

### JWT 不适用于

- **需要即时吊销的场景** — JWT 签发后无法撤销（除非维护 blacklist，但这又变成有状态的了）
- **长时间登录状态** — 依赖 Refresh Token（有状态）来续命
- **传统服务端渲染应用** — Session Auth 更简单直接

### 从 API Key 到 JWT 解决了什么？

| API Key 的局限 | JWT 怎么解决的 |
|---|---|
| 不包含用户信息 | Payload 中包含 Claims（sub, email, role） |
| 没有过期机制 | 内置 `exp` Claim 自动过期 |
| 没有权限范围 | Claims 可以表达任意权限信息 |
| 需要查数据库验证 | 签名验证即可，不查库 |

---

## Part 8：模块总结与自查清单

### 安全清单

- [ ] 每个 `verify()` 调用都**显式指定允许的算法**（防御 Algorithm Confusion）
- [ ] 生产环境使用**非对称算法**（RS256 / ES256）
- [ ] Access Token 生命周期 **≤ 15 分钟**
- [ ] Refresh Token 存数据库，支持**吊销和 Reuse Detection**
- [ ] JWT Payload **不含敏感信息**
- [ ] 验证 `iss`, `aud`, `exp` Claims
- [ ] Private Key **不提交到 Git**

### 概念自查

- [ ] 我能解释 JWT 的三段式结构和每段的作用
- [ ] 我能手动 Base64 解码 JWT Payload
- [ ] 我能解释 HS256 和 RS256 的区别以及为什么微服务要用 RS256
- [ ] 我能解释 Algorithm Confusion 攻击的原理和防御方法
- [ ] 我能解释为什么 Access Token 要短、Refresh Token 要长
- [ ] 我能解释 Refresh Token Rotation 和 Reuse Detection 的流程
- [ ] 我能解释为什么 Refresh Token 不应该是 JWT
- [ ] 我知道 JWT 适合和不适合的使用场景

---

## 下一步

完成本 Module 后，进入 [Module 05 — OAuth 2.0 / 2.1](../05-oauth2/README.md)。

到目前为止，所有认证机制（Basic Auth → Session → API Key → JWT）都是**你的应用自己管理凭证**。OAuth 2.0 引入了一个全新的概念——**委托授权**：

1. **用户不需要把密码给你** — "Login with Google" 让用户在 Google 那边登录，你的应用只收到一个授权 Token
2. **权限可以精细控制** — 用户可以只授权"读取邮箱"而不是"完全访问 Google 账号"
3. **第三方生态** — 开发者可以构建基于你的平台的应用（如 GitHub App、Slack Bot）

---

## 参考资料

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jose npm package](https://www.npmjs.com/package/jose) — 零依赖跨运行时 JWT 库
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [jwt.io](https://jwt.io) — JWT 解码器和调试器
- [JWT Algorithm Confusion: 2026 CVEs](https://dev.to/hari_prakash_b0a882ec9225/jwt-algorithm-confusion-attack-two-active-cves-in-2026-7bc)
- [Auth0 — Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
