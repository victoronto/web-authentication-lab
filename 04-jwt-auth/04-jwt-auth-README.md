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
pip install Flask PyJWT cryptography bcrypt
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

创建 `app.py`

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
