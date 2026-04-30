# Module 02 — Session-based Authentication

> 用服务端状态解决 Basic Auth 的两大核心缺陷：每次请求都传输凭证 & 没有 Logout 机制。

---

## 学习目标

完成本 Module 后，你将能够：

- 理解 Session Auth 的完整生命周期（登录 → 创建 Session → Cookie → 请求验证 → Logout 销毁）
- 解释 Session Auth 和 Basic Auth 的本质区别
- 用 Node.js 从零实现 Session Middleware（不依赖 Passport）
- 用 Passport.js + `passport-local` 重构，理解框架抽象层
- 用 Python Flask-Session + Redis 实现同样的功能
- 理解 Cookie 的安全属性（`HttpOnly`, `Secure`, `SameSite`）及其防御目标
- 理解并防御 Session Fixation 攻击（Session ID Regeneration）
- 理解并防御 CSRF 攻击（CSRF Token）
- 配置 Redis 作为 Session Store 并用 `redis-cli` 检查 Session 数据
- 实现 Idle Timeout 和 Absolute Timeout 双重超时机制
- 用 `curl` 和 `HTTPie` 从命令行测试 Session 认证端点

---

## 前置准备

```bash
# 确保你在 repo 的 Module 02 目录
cd web-auth-learning/02-session-auth

# 创建子目录
mkdir -p node python tests

# 启动 Redis（Docker）- it's actually have been started in ../docker folder by compose as docker-redis-1
# docker run -d --name redis -p 6379:6379 redis:latest

# 验证 Redis 运行状态
docker exec -it docker-redis-1 redis-cli ping
# 期望输出: PONG
```

---

## Part 1：理论 — Session Auth 协议机制

### 这是什么？

Session Authentication 是**有状态**的认证方式。用户登录时凭证只传输**一次**，服务端验证通过后创建一个 Session（存储在 Redis/数据库中），并通过 `Set-Cookie` 向客户端发送一个 Session ID。之后的每个请求，浏览器自动携带这个 Cookie，服务端通过 Session ID 查找对应的 Session 数据来验证用户身份。

### 与 Basic Auth 的关键区别

回顾 Module 01 的两个核心问题：

| 问题 | Basic Auth | Session Auth |
|------|-----------|--------------|
| 凭证传输频率 | **每个请求**都传输 username:password | 只在**登录时**传输一次 |
| Logout 机制 | 没有（浏览器缓存凭证，关闭浏览器才能"登出"） | 有——服务端**销毁 Session** |
| 状态 | 无状态（Stateless） | 有状态（Stateful） |
| 存储 | 客户端每次都发送凭证 | 服务端存储 Session 数据 |

### 完整的 Session Auth 流程

```
CLIENT                                          SERVER                    REDIS
  |                                               |                         |
  |  1) POST /login                               |                         |
  |  Body: { email, password }                    |                         |
  |  （凭证只传输这一次）                            |                         |
  |---------------------------------------------->|                         |
  |                                               |                         |
  |  2) 验证凭证 (bcrypt.compare)                  |                         |
  |  3) 创建 Session                               |                         |
  |                                               |-- SET sess:abc123 -->   |
  |                                               |   { userId: 42, ... }   |
  |                                               |                         |
  |  4) HTTP/1.1 200 OK                           |                         |
  |  Set-Cookie: sessionId=abc123;                |                         |
  |    HttpOnly; Secure; SameSite=Lax             |                         |
  |<----------------------------------------------|                         |
  |                                               |                         |
  |  5) GET /api/notes                            |                         |
  |  Cookie: sessionId=abc123                     |                         |
  |  （浏览器自动附带 Cookie，不需要手动处理）         |                         |
  |---------------------------------------------->|                         |
  |                                               |-- GET sess:abc123 -->   |
  |                                               |<-- { userId: 42 } --    |
  |                                               |                         |
  |  6) 200 OK + 用户数据                           |                         |
  |<----------------------------------------------|                         |
  |                                               |                         |
  |  7) POST /logout                              |                         |
  |  Cookie: sessionId=abc123                     |                         |
  |---------------------------------------------->|                         |
  |                                               |-- DEL sess:abc123 -->   |
  |                                               |                         |
  |  8) Set-Cookie: sessionId=; Max-Age=0         |                         |
  |  （服务端销毁 Session + 清除客户端 Cookie）       |                         |
  |<----------------------------------------------|                         |
```

**关键认知：** Session ID 本身不包含任何用户信息——它只是一个随机字符串，像是一张"取物票"。真正的用户数据存在服务端（Redis）。这跟 Module 04 的 JWT 形成鲜明对比——JWT 是自包含的，Payload 里直接携带用户信息。

### Cookie 安全属性（必须掌握）

Cookie 是 Session Auth 的传输载体。如果 Cookie 配置不当，Session ID 就可能被窃取。

| 属性 | 作用 | 防御的攻击 | 设置 |
|------|------|-----------|------|
| `HttpOnly` | 阻止 JavaScript 通过 `document.cookie` 访问 | XSS 窃取 Session ID | `true`（必须） |
| `Secure` | Cookie 仅通过 HTTPS 传输 | 中间人截获 Session ID | `true`（生产环境） |
| `SameSite` | 限制跨站请求时 Cookie 的发送 | CSRF 攻击（纵深防御） | `Lax`（推荐） |
| `Max-Age` | Cookie 过期时间（秒） | 过期 Session 的滥用 | 根据业务设定 |

**`SameSite` 的三个值：**

- `Strict` — 跨站请求**完全不发送** Cookie。最安全，但用户从外部链接点进来时会丢失登录状态（体验差）。
- `Lax`（推荐）— 跨站的 **GET 导航**（点击链接、输入地址）会发送 Cookie，但跨站的 POST/PUT/DELETE **不发送**。平衡了安全和用户体验。
- `None` — 跨站请求**总是发送** Cookie（必须同时设置 `Secure`）。仅用于需要跨站认证的场景（如嵌入式 iframe）。

**重要：** OWASP 明确指出 `SameSite` **不能替代 CSRF Token**——它只是纵深防御的一层。原因包括：子域攻击可以绕过、Chrome 对新设置的 Lax Cookie 有 2 分钟的 POST 宽限期、浏览器行为不完全一致。

### Session Fixation 攻击（必须理解）

**攻击流程：**

1. 攻击者访问你的网站，获得一个有效的 Session ID（比如 `sess:evil123`）
2. 攻击者通过某种方式让受害者使用这个 Session ID（URL 注入、XSS 设置 Cookie 等）
3. 受害者用 `sess:evil123` 这个 Session 登录了
4. 攻击者用同样的 `sess:evil123` 访问网站——此时这个 Session 已经是"已登录"状态

**防御：** 登录成功后**必须 regenerate Session ID**。旧的 Session ID 失效，生成新的 Session ID 绑定到已认证的用户。这样即使攻击者拿到了旧的 Session ID，也没用了。

```
登录前: sess:evil123 → { authenticated: false }
登录后: sess:evil123 → 销毁
        sess:NEW789  → { userId: 42, authenticated: true }  ← 新 ID
```

### CSRF 攻击（必须理解）

**CSRF（Cross-Site Request Forgery，跨站请求伪造）** 利用的是浏览器**自动附带 Cookie** 的行为。

**攻击场景：**

1. 你已经登录了 `bank.com`，浏览器里有有效的 Session Cookie
2. 你访问了恶意网站 `evil.com`
3. `evil.com` 的页面里偷偷放了一个表单：
   ```html
   <form action="https://bank.com/transfer" method="POST">
     <input type="hidden" name="to" value="attacker">
     <input type="hidden" name="amount" value="10000">
   </form>
   <script>document.forms[0].submit();</script>
   ```
4. 浏览器发送 POST 请求到 `bank.com/transfer`，**自动附带你的 Session Cookie**
5. `bank.com` 收到请求，Session 有效，执行转账

**防御：** 使用 CSRF Token。服务端生成一个随机 Token，嵌入到表单中。提交时服务端验证这个 Token——攻击者无法获取这个 Token（因为它不在 Cookie 里，而是在页面内容中），所以伪造的请求无法通过验证。

---

## Part 2：动手实践 — Node.js 实现

### Step 1：初始化项目

```bash
cd 02-session-auth/node
npm init -y
npm install express express-session connect-redis redis bcrypt
```

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `express-session` | 1.19.0 | Express 的 Session Middleware |
| `connect-redis` | 9.0.0 | 将 Session 存储到 Redis |
| `redis` (node-redis) | 5.x | Redis 客户端 |
| `bcrypt` | 6.0.0 | 密码哈希（Module 01 已学过） |

> **注意：** `connect-redis` v9 **移除了对 `ioredis` 的支持**，只支持 `redis`（node-redis）。如果你在网上看到用 `ioredis` 的教程，那已经过时了。`ioredis` 的 README 本身也推荐新项目使用 node-redis。

> **`connect-redis` 的 API 变化史（踩坑防护）：**
> - v6 及更早：`const RedisStore = require('connect-redis')(session)` — 需要传入 session
> - v7：`import RedisStore from 'connect-redis'` — default export
> - v8：`import { RedisStore } from 'connect-redis'` — named export
> - v9（当前）：`import { RedisStore } from 'connect-redis'` — named export + **移除 ioredis 支持**
> 
> 网上很多教程还停留在 v6/v7 的写法，直接复制会报错。

### Step 2：从零构建 Session Auth（不用 Passport）

**为什么先不用 Passport？** 跟 Module 01 一样——先理解底层机制。你需要知道 `express-session` 做了什么、Session ID 是怎么生成的、Cookie 是怎么设置的，才能真正理解 Passport 在此基础上提供了什么。
创建 `server-raw.js`

#### troubleshooting
> **关于 ES Modules：** 上面的代码使用了 `import` 语法。你需要在 `package.json` 中添加 `"type": "module"`，或者把所有 `import` 改成 `require`。如果你用 `require`：
```javascript
const express = require('express');
const session = require('express-session');
const { RedisStore } = require('connect-redis');
const { createClient } = require('redis');
const bcrypt = require('bcrypt');
```
Module 01 用的是 `require`（CommonJS），这里我们切换到 `import`（ES Modules）让你接触两种风格。两种方式功能完全一样，只是语法不同。
```bash
vscode ➜ /workspaces/web-authentication-lab/02-session-auth/node (2) $ node server-raw.js
(node:18146) Warning: Failed to load the ES module: /workspaces/web-authentication-lab/02-session-auth/node/server-raw.js. Make sure to set "type": "module" in the nearest package.json file or use the .mjs extension.
(Use node --trace-warnings ... to show where the warning was created)
/workspaces/web-authentication-lab/02-session-auth/node/server-raw.js:2
import express from 'express';
^^^^^^
SyntaxError: Cannot use import statement outside a module
    at wrapSafe (node:internal/modules/cjs/loader:1763:18)
    at Module._compile (node:internal/modules/cjs/loader:1804:20)
    at Object..js (node:internal/modules/cjs/loader:1961:10)
    at Module.load (node:internal/modules/cjs/loader:1553:32)
    at Module._load (node:internal/modules/cjs/loader:1355:12)
    at wrapModuleLoad (node:internal/modules/cjs/loader:255:19)
    at Module.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:154:5)
    at node:internal/main/run_main_module:33:47
Node.js v24.15.0
```

### Step 3：运行并测试

```bash
node server-raw.js
```

**打开另一个 terminal，用 curl 测试完整的 Session 生命周期：**

```bash
# ============================================
# 测试 1: 公开端点（不需要登录）
# ============================================
curl http://localhost:3000/health
# 期望: {"status":"ok","timestamp":"..."}

# ============================================
# 测试 2: 未登录访问受保护端点
# ============================================
curl http://localhost:3000/api/notes
# 期望: {"error":"Not authenticated. Please login first."}

# ============================================
# 测试 3: 登录（凭证只传输这一次！）
# ============================================
# -c cookies.txt 将服务端返回的 Set-Cookie 保存到文件
# -H 设置 Content-Type 为 JSON
curl -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/login
# 期望: {"message":"Login successful","user":{"id":1,...}}

# 查看 curl 保存的 Cookie 文件
cat cookies.txt
# 你会看到类似:
# localhost  FALSE  /  FALSE  0  sessionId  s%3A<signed-session-id>
# 注意 sessionId 的值被签名过（s%3A 前缀），这是 express-session 的安全机制

# ============================================
# 测试 4: 携带 Cookie 访问受保护端点
# ============================================
# -b cookies.txt 在请求中附带保存的 Cookie
curl -b cookies.txt http://localhost:3000/api/notes
# 期望: {"notes":[...],"user":"admin@example.com"}
# 注意：这里不需要再发送 email/password！Cookie 就是你的"通行证"

# ============================================
# 测试 5: 查看 Session 详情（调试）
# ============================================
curl -b cookies.txt http://localhost:3000/debug/session
# 期望: { sessionId, cookie 信息, 用户数据 }

# ============================================
# 测试 6: 登出
# ============================================
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:3000/logout
# 期望: {"message":"Logged out successfully"}

# ============================================
# 测试 7: 登出后再访问受保护端点
# ============================================
curl -b cookies.txt http://localhost:3000/api/notes
# 期望: {"error":"Not authenticated. Please login first."}
# Session 已被服务端销毁，Cookie 无效了

# ============================================
# 测试 8: 详细模式 — 观察 Set-Cookie 和 Cookie Header
# ============================================
curl -v -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/login
# 关键观察:
# < Set-Cookie: sessionId=s%3A...; Path=/; HttpOnly; SameSite=Lax
#   ↑ 服务端设置 Cookie
# 后续请求:
curl -v -b cookies.txt http://localhost:3000/api/notes
# > Cookie: sessionId=s%3A...
#   ↑ 客户端自动附带 Cookie
```
### 我们学到了什么？

对比 Module 01 的 `curl -u admin:secret123`：

| 维度 | Basic Auth (Module 01) | Session Auth (Module 02) |
|------|----------------------|-------------------------|
| 凭证传输 | 每个 `curl` 命令都要 `-u admin:secret123` | 只有 `/login` 发送凭证，之后用 `-b cookies.txt` |
| 认证载体 | `Authorization: Basic xxx` Header | `Cookie: sessionId=xxx` Header |
| Logout | 不可能（除非关闭浏览器） | `POST /logout` 服务端销毁 Session |
| 服务端状态 | 无（每次请求都要重新验证密码） | 有（Redis 中存储 Session 数据） |

---

### Step 4：在 Redis 中检查 Session

这一步非常重要——它让你**亲眼看到** Session 在服务端是怎么存储的。

```bash
# 进入 Redis CLI
docker exec -it redis redis-cli

# 列出所有 Session key
KEYS sess:*
# 期望输出: 1) "sess:abc123def456..."

# 查看 Session 数据（JSON 格式）
GET sess:abc123def456
# 期望输出: {"cookie":{...},"userId":1,"email":"admin@example.com","role":"admin","createdAt":...}

# 查看 Session 的剩余生存时间（TTL，秒）
TTL sess:abc123def456
# 期望输出: 1800 左右（30 分钟 = 1800 秒）
# -1 表示没有过期时间，-2 表示 key 已经不存在了

# 手动删除一个 Session（等同于服务端 logout）
DEL sess:abc123def456

# 生产环境中不要用 KEYS 命令（会阻塞 Redis）
# 用 SCAN 代替（非阻塞，游标式遍历）
SCAN 0 MATCH sess:* COUNT 100
```

### 我们学到了什么？

- Session 数据**存储在 Redis 中**，不是在客户端——客户端只有一个 Session ID
- Session ID 对应 Redis 中的一个 key（如 `sess:abc123`），value 是序列化的 Session 数据
- `TTL` 显示剩余生存时间——每次请求都会重置（因为 `express-session` 的 touch 机制），这就是 Idle Timeout 的实现原理
- 手动 `DEL` 一个 Session key 等同于强制登出该用户——这就是服务端 Logout 的本质

---

### Step 5：为什么绝不能用 MemoryStore？

`express-session` 默认使用 MemoryStore（内存存储），启动时会输出一条警告：

```
Warning: connect.session() MemoryStore is not
designed for a production environment, as it will leak
memory, and will not scale past a single process.
```

**三个致命问题：**

1. **内存泄漏** — MemoryStore **不会自动清理过期的 Session**。一个每天处理 10,000 个 Session 的站点，一年会积累约 365 万个僵尸 Session，直到进程内存耗尽崩溃。

2. **不支持水平扩展** — 如果你有多个 Node.js 进程（PM2 cluster mode）或多台服务器（Load Balancer 后面），每个进程的 MemoryStore 是独立的。用户在 Server A 上登录，下次请求被分配到 Server B，Server B 找不到 Session——用户突然变成"未登录"状态。Redis 是共享的外部存储，所有进程/服务器都连接同一个 Redis。

3. **进程重启 = 全部 Session 丢失** — 代码部署、进程崩溃或服务器重启时，内存中的所有 Session 立即消失。所有在线用户瞬间被强制登出。Redis 的数据持久化在磁盘上，重启后 Session 还在。

```
这跟 AWS 的场景完全一样

[EC2 A] ──── MemoryStore (sessions: {sess:1, sess:2})
   ↑
[ALB] ──── Load Balancer
   ↓
[EC2 B] ──── MemoryStore (sessions: {})  ← 这里没有 sess:1

用户在 EC2 A 上登录，下次请求被分配到 EC2 B → 401 Unauthorized

解决方案：
[EC2 A] ──── 
   ↑         ↘
[ALB]         [ElastiCache Redis] ← 共享 Session Store
   ↓         ↗
[EC2 B] ────

现在两台 EC2 都连接同一个 Redis，Session 数据共享。
Auto Scaling Group 加减机器也不影响 Session。
```

---

### Step 6：添加 CSRF 保护

**为什么需要 CSRF Token？** Part 1 已经解释了 CSRF 攻击原理。`SameSite=Lax` 能防御大部分 CSRF，但它不是银弹。OWASP 推荐 CSRF Token 作为主要防御手段，`SameSite` 作为纵深防御。

**`csurf` 已废弃！** 如果你在网上看到 `npm install csurf` 的教程，那已经过时了。`csurf` 在 2022 年 9 月被废弃，2025 年 5 月被 Express 团队正式确认弃用。

目前推荐的替代方案来自同一个作者（Psifi-Solutions）：

| 包 | 模式 | 需要 Session？ | 适用场景 |
|---|------|---------------|---------|
| **`csrf-sync`** | Synchronizer Token（有状态） | 是 | **Session-based 应用（就是我们的场景）** |
| `csrf-csrf` | Double Submit Cookie（无状态） | 否 | SPA / 无状态 API |

我们用 `csrf-sync`，因为它跟 Session 天然配合：

```bash
npm install csrf-sync
```
Update `server-raw.js` 添加 CSRF：

### 测试 CSRF 保护

```bash
# 1. 登录（获取 Session Cookie）
curl -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/login

# 2. 获取 CSRF Token
curl -b cookies.txt http://localhost:3000/csrf-token
# 期望: {"csrfToken":"some-random-token-value"}

# 3. 发送 POST 请求（不带 CSRF Token）— 应该失败
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"title":"New Note","body":"Content"}' \
  -X POST http://localhost:3000/api/notes
# 期望: 403 {"error":"Invalid or missing CSRF token"}

# 4. 发送 POST 请求（带 CSRF Token）— 应该成功
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <粘贴第2步获得的token>" \
  -d '{"title":"New Note","body":"Content"}' \
  -X POST http://localhost:3000/api/notes
# 期望: 201 {"message":"Note created",...}
```

### 我们学到了什么？

- `csrf-sync` 将 CSRF Token 存储在 `req.session.csrfToken` 中（Session 里），所以它只对已登录用户有意义
- GET 请求自动跳过 CSRF 检查（GET 应该是幂等的，不修改数据）
- CSRF Token 通过 Header（`X-CSRF-Token`）发送，**不是** Cookie——这是关键区别。攻击者的跨站请求可以自动附带 Cookie，但**无法读取你页面上的 CSRF Token**
- 在浏览器前端中，通常先 `fetch('/csrf-token')` 获取 Token，然后在后续 POST 请求的 Header 中附带

---

### Step 7：用 Passport.js + passport-local 重构

**为什么用 Passport？** 跟 Module 01 一样——对比手动实现和框架的差异。Module 01 用了 `passport-http`（BasicStrategy），这里我们用 `passport-local`（LocalStrategy），配合 Session 实现"登录一次，后续请求自动认证"。

```bash
npm install passport passport-local
```

创建 `server-passport.js`：

```javascript
// server-passport.js — Passport.js + passport-local + Session
import express from 'express';
import session from 'express-session';
import { RedisStore } from 'connect-redis';
import { createClient } from 'redis';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());
const PORT = 3002;

// Redis + Session 配置（同前）
const redisClient = createClient({ url: 'redis://localhost:6379' });
redisClient.connect().catch(console.error);

app.use(session({
  store: new RedisStore({ client: redisClient, prefix: 'sess:' }),
  secret: 'change-me-to-a-strong-random-string',
  name: 'sessionId',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 1000 * 60 * 30 },
}));

// ============================================
// 模拟用户数据库
// ============================================
const users = {};

async function initUsers() {
  users[1] = {
    id: 1,
    email: 'admin@example.com',
    passwordHash: await bcrypt.hash('secret123', 12),
    role: 'admin',
  };
  users[2] = {
    id: 2,
    email: 'viewer@example.com',
    passwordHash: await bcrypt.hash('readonly456', 12),
    role: 'viewer',
  };
}

function findUserByEmail(email) {
  return Object.values(users).find((u) => u.email === email);
}

// ============================================
// Passport 配置
// ============================================

// 1. 定义验证策略
passport.use(new LocalStrategy(
  { usernameField: 'email' }, // 告诉 Passport 用 req.body.email 而不是默认的 req.body.username
  async (email, password, done) => {
    try {
      const user = findUserByEmail(email);
      const dummyHash = '$2b$12$LJ3m4ys3Lk0TSwHjpF2gT.UzIR3WH9CPNRGK/7e7e3jY3CSJiXZ2e';
      const isMatch = await bcrypt.compare(password, user?.passwordHash || dummyHash);

      if (!user || !isMatch) {
        return done(null, false, { message: 'Invalid email or password' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// 2. 序列化：登录成功后，决定哪些信息存入 Session
//    这里只存 user.id（最小化 Session 数据）
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// 3. 反序列化：每个请求时，根据 Session 中的 id 恢复完整用户对象
//    恢复后的用户对象挂载到 req.user
passport.deserializeUser((id, done) => {
  const user = users[id];
  if (!user) return done(null, false);
  done(null, { id: user.id, email: user.email, role: user.role });
});

// ★ Middleware 顺序很重要：session → passport.initialize → passport.session
app.use(passport.initialize());
app.use(passport.session());

// ============================================
// 路由
// ============================================

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// 登录
// Passport 0.6+ 在 req.login() 时自动调用 req.session.regenerate()
// 所以你不需要手动做 Session Fixation 防御
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: info.message });

    // req.login() 触发 serializeUser，将 user.id 存入 Session
    // Passport 0.6+ 在这里自动 regenerate Session ID
    req.login(user, (err) => {
      if (err) return next(err);
      res.json({
        message: 'Login successful',
        user: { id: user.id, email: user.email, role: user.role },
      });
    });
  })(req, res, next);
});

// 登出
// ★ Passport 0.6+ 的 req.logout() 变成了异步的
// 旧写法 req.logout(); res.redirect('/') 会静默失败！
app.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie('sessionId');
      res.json({ message: 'Logged out' });
    });
  });
});

// 受保护路由
const requireAuth = (req, res, next) => {
  if (!req.isAuthenticated()) { // Passport 提供的方法
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ user: req.user }); // req.user 由 deserializeUser 填充
});

app.get('/api/notes', requireAuth, (req, res) => {
  res.json({
    notes: [
      { id: 1, title: 'Passport.js Session Auth' },
      { id: 2, title: 'serializeUser and deserializeUser' },
    ],
    user: req.user,
  });
});

initUsers().then(() => {
  app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
});
```

### Passport 的 serialize / deserialize 是什么？

这是 Session Auth 中最容易困惑的概念，画个图就清楚了：

```
登录时（serializeUser）:
  user 对象 { id:1, email:'...', passwordHash:'...' }
       ↓ serializeUser
  Session 中只存 1 (user.id)
  为什么？ passwordHash 这类敏感数据不应该存在 Session 里

每个后续请求（deserializeUser）:
  Session 中读出 1 (user.id)
       ↓ deserializeUser
  数据库查询 → 返回 { id:1, email:'...', role:'admin' }
       ↓
  挂载到 req.user（不包含 passwordHash）
```

### 我们学到了什么？

对比两种实现方式：

| 对比维度 | Raw Middleware | Passport.js |
|---------|---------------|-------------|
| Session 创建 | 手动 `req.session.userId = ...` | `req.login()` + `serializeUser` |
| Session 读取 | 手动 `req.session.userId` | 自动 `deserializeUser` → `req.user` |
| Session Regeneration | 手动 `req.session.regenerate()` | Passport 0.6+ **自动**处理 |
| Logout | 手动 `req.session.destroy()` | `req.logout()` + `req.session.destroy()` |
| 认证检查 | `if (!req.session.userId)` | `req.isAuthenticated()` |
| 可扩展性 | 单一用途 | 可切换 Strategy（Google, GitHub, SAML 等） |

**核心收获：**

- Passport 的 `serializeUser` / `deserializeUser` 是 Session Auth 的核心抽象——决定了 Session 中存什么（最小化）和每个请求恢复什么
- Passport 0.6+ 做了一个重要的安全改进：`req.login()` 自动 regenerate Session ID（防御 Session Fixation），`req.logout()` 变成异步（必须传 callback）
- 如果你需要保留登录前的 Session 数据（比如购物车），可以传 `{ keepSessionInfo: true }` 给 `passport.authenticate()`

---

## Part 3：动手实践 — Python 实现

### Step 1：初始化项目

```bash
cd 02-session-auth/python

# 确保使用 Python 3.13（Module 01 已配置 pyenv local 3.13.9）
python3 --version
# 期望: Python 3.13.9

python3 -m venv venv
source venv/bin/activate
pip install Flask Flask-Session Flask-WTF Flask-Bcrypt redis
```

**包说明：**

| 包 | 版本 | 用途 |
|---|------|------|
| `Flask-Session` | 0.8.0 | Flask 的服务端 Session 扩展 |
| `Flask-WTF` | 1.2.2 | CSRF 保护（替代 Node.js 的 `csrf-sync`） |
| `Flask-Bcrypt` | 1.0.1 | 密码哈希 |
| `redis` (redis-py) | 7.1.1 | Redis 客户端（需要 Python ≥ 3.10） |

> **注意：** `redis-py` 7.x 需要 Python ≥ 3.10。如果你因为某种原因还在用 Python 3.9，需要 `pip install "redis<7"`。Module 01 中你已经通过 pyenv 升级到了 3.13.9，所以不用担心。

> **Flask-Session 0.7+ 的重要变化：** 默认序列化格式从 `pickle` 切换到了 `msgpack`（体积更小约 30%）。如果你之前用旧版 Flask-Session 存过 Session，升级到 0.7+ 后旧 Session 会被自动清理。

### Step 2：用 Flask-Session + Redis 实现

创建 `app.py`：

```python
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
    SESSION_REDIS=redis.Redis(host='localhost', port=6379, db=0),
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
```

### Step 3：运行并测试

```bash
python app.py
```

```bash
# ============================================
# 测试完整生命周期（跟 Node.js 版本一样的流程）
# ============================================

# 1. 公开端点
curl http://localhost:5001/health

# 2. 未登录
curl http://localhost:5001/api/notes
# 期望: 401

# 3. 登录
curl -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:5001/login

# 4. 访问受保护端点
curl -b cookies.txt http://localhost:5001/api/notes
# 期望: {"notes":[...],"user":"admin@example.com"}

# 5. 获取 CSRF Token
curl -b cookies.txt http://localhost:5001/csrf-token
# 期望: {"csrfToken":"..."}

# 6. 创建笔记（需要 CSRF Token）
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: <粘贴csrf-token>" \
  -d '{"title":"New Note","body":"Content"}' \
  -X POST http://localhost:5001/api/notes
# 期望: 201

# 7. 登出
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:5001/logout

# 8. 登出后访问
curl -b cookies.txt http://localhost:5001/api/notes
# 期望: 401
```

### Step 4：用 Python requests 作为客户端测试

创建 `test_client.py`：

```python
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
```

```bash
python test_client.py
```

### 我们学到了什么？

- `requests.Session()` 自动管理 Cookie——类似浏览器行为，登录后的请求自动携带 Session Cookie
- Flask-Session 0.8.0 的 `regenerate()` 方法需要 Session **非空**才能工作（空 dict 是 falsy），所以**先写数据，再 regenerate**
- Flask-WTF 的 CSRF Token 通过 `X-CSRFToken` Header 发送（注意是 `CSRFToken` 不是 `CSRF-Token`，这跟 Node.js 的 `X-CSRF-Token` 命名习惯不同）
- Port 5000 要避开——Module 01 中你已经踩过 macOS AirPlay Receiver 占用 5000 的坑

---

## Part 4：安全演示

### 演示 1：Session Fixation 攻击

**没有 Session Regeneration 时会发生什么：**

```bash
# 1. 攻击者获取一个 Session ID
curl -c attacker-cookies.txt http://localhost:3000/health
cat attacker-cookies.txt
# 假设 Session ID 是 abc123

# 2. 攻击者把这个 Session ID 通过某种方式给了受害者
#   （URL 注入、XSS 设置 Cookie 等）

# 3. 受害者用 abc123 这个 Session 登录
#   如果登录后 Session ID 不变，那么...

# 4. 攻击者用同样的 abc123 访问
curl -b attacker-cookies.txt http://localhost:3000/api/profile
# 如果没有 regenerate: 200 OK — 攻击成功！
# 如果有 regenerate: 401 — abc123 已失效，攻击者拿不到新 ID
```

**我们的实现中**，`req.session.regenerate()`（Node.js）和 `app.session_interface.regenerate(session)`（Flask）在登录成功后立即生成新的 Session ID，旧的被销毁。所以即使攻击者拿到了登录前的 Session ID，也没用。

### 演示 2：Cookie 安全属性的效果

```bash
# 用 curl -v 观察 Set-Cookie Header
curl -v -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/login

# 观察响应中的 Set-Cookie:
# < Set-Cookie: sessionId=s%3A...; Path=/; HttpOnly; SameSite=Lax
#
# HttpOnly — 浏览器中 JavaScript 无法通过 document.cookie 读取这个 Cookie
# SameSite=Lax — 跨站 POST 请求不会发送这个 Cookie（防 CSRF）
# 没有 Secure — 因为我们在开发环境（HTTP），生产环境会有 Secure 标记
```

### 演示 3：MemoryStore 的 Session 泄漏

```javascript
// 不要在生产环境运行这个！仅作为演示
// memory-leak-demo.js
import express from 'express';
import session from 'express-session';

const app = express();
app.use(session({
  secret: 'test',
  resave: false,
  saveUninitialized: true, // ← 每个请求都创建 Session
  cookie: { maxAge: 60000 },
}));

app.get('/', (req, res) => {
  req.session.counter = (req.session.counter || 0) + 1;
  res.json({ counter: req.session.counter });
});

app.listen(3099, () => {
  console.log('MemoryStore demo on :3099');
  // 观察内存使用: process.memoryUsage().heapUsed
  setInterval(() => {
    const mb = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2);
    console.log(`Heap: ${mb} MB`);
  }, 5000);
});
```

用 `for i in $(seq 1 10000); do curl -s http://localhost:3099/ > /dev/null; done` 快速创建大量 Session，观察内存持续增长且不会回落——因为 MemoryStore 不清理过期 Session。

---

## Part 5：测试工具速查

### curl 命令

```bash
# ---- 登录并保存 Cookie ----
curl -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secret123"}' \
  http://localhost:3000/login

# ---- 携带 Cookie 访问受保护端点 ----
curl -b cookies.txt http://localhost:3000/api/notes

# ---- 详细模式（观察 Set-Cookie 和 Cookie Header）----
curl -v -b cookies.txt http://localhost:3000/api/profile

# ---- POST 请求带 CSRF Token ----
curl -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <token>" \
  -d '{"title":"Note","body":"Content"}' \
  -X POST http://localhost:3000/api/notes

# ---- 登出 ----
curl -b cookies.txt -c cookies.txt -X POST http://localhost:3000/logout

# ---- curl 参数说明 ----
# -c cookies.txt  将服务端的 Set-Cookie 保存到文件
# -b cookies.txt  在请求中发送文件里的 Cookie
# -H              添加自定义 Header
# -d              请求体（自动设为 POST，除非用 -X 指定）
# -X POST         显式指定 HTTP 方法
# -v              详细模式，显示完整的 HTTP 交互
```

### HTTPie 命令

```bash
# ---- 登录（HTTPie 用 --session 自动管理 Cookie）----
http POST :3000/login email=admin@example.com password=secret123 --session=dev

# ---- 携带 Session 访问受保护端点 ----
http :3000/api/notes --session=dev

# ---- POST 带 CSRF Token ----
http POST :3000/api/notes title="Note" body="Content" \
  X-CSRF-Token:<token> --session=dev

# ---- 登出 ----
http POST :3000/logout --session=dev

# ---- 详细模式 ----
http -v :3000/api/profile --session=dev
```

> **HTTPie 的 `--session=dev` 比 curl 的 `-c/-b cookies.txt` 更方便**——它自动保存和发送 Cookie，跨请求保持 Session。这非常适合测试 Session Auth。

### Redis CLI 命令

```bash
docker exec -it redis redis-cli

# 查看所有 Session
KEYS sess:*          # 开发环境用
SCAN 0 MATCH sess:*  # 生产环境用（非阻塞）

# 查看 Session 数据
GET sess:<session-id>

# 查看剩余 TTL
TTL sess:<session-id>

# 手动删除 Session（强制登出）
DEL sess:<session-id>

# 清空所有 Session
FLUSHDB   # ⚠️ 会清空整个数据库
```

---

## Part 6：Node.js 与 Python 实现对比

| 维度 | Node.js (Express) | Python (Flask) |
|------|-------------------|----------------|
| Session 中间件 | `express-session` | `Flask-Session` |
| Redis 连接 | `redis` (node-redis) | `redis` (redis-py) |
| Redis Store 适配 | `connect-redis` v9 | `Flask-Session` 内置 |
| 密码哈希 | `bcrypt` | `Flask-Bcrypt` |
| CSRF 保护 | `csrf-sync` | `Flask-WTF` (CSRFProtect) |
| Session Regeneration | `req.session.regenerate(callback)` | `app.session_interface.regenerate(session)` |
| Session 销毁 | `req.session.destroy(callback)` | `session.clear()` |
| Cookie 配置 | `session({ cookie: {...} })` | `app.config['SESSION_COOKIE_*']` |
| Passport 等价物 | `passport` + `passport-local` | `Flask-Login`（本 Module 未使用） |
| 序列化格式 | JSON（默认） | msgpack（Flask-Session 0.7+ 默认） |

---

## Part 7：适用场景与局限性

### Session Auth 适用于

- 传统的服务端渲染 Web 应用（模板引擎 + 表单提交）
- 需要**真正的 Logout 机制**的场景
- 需要**服务端控制 Session 生命周期**的场景（管理员强制登出用户）
- 需要 **CSRF 防护**的场景
- 内部管理后台

### Session Auth 不适用于

- **纯 API 服务**（供移动端/第三方调用）— 没有浏览器就没有 Cookie，用 JWT (Module 04) 更合适
- **无状态微服务架构** — Session 是有状态的，需要共享 Session Store（Redis）。JWT 是无状态的，每个微服务可以独立验证
- **跨域场景**（不同域名下的 SPA 调用 API）— Cookie 的 SameSite 和 Domain 限制会造成问题

### 从 Basic Auth 到 Session Auth 解决了什么？

| Basic Auth 的问题 | Session Auth 怎么解决的 |
|---|---|
| 每次请求都传输密码 | 密码只传输一次（登录时），之后用 Session ID |
| 没有 Logout | 服务端销毁 Session 即可登出 |
| 没有 CSRF 防护 | Session + CSRF Token 组合防御 |
| 密码在客户端缓存 | Session ID 不是密码，且有过期机制 |

### Session Auth 引入了什么新问题？

| 新问题 | 这正是后续 Module 要解决的 |
|---|---|
| 需要服务端存储（有状态） | Module 04: JWT（无状态 Token） |
| 不适合跨域 API | Module 04: JWT + Module 05: OAuth 2.0 |
| 水平扩展需要共享 Session Store | Module 04: JWT（无需共享存储） |

---

## Part 8：模块总结与自查清单

### 安全清单

- [ ] 使用 Redis（或其他外部 Store）存储 Session，**不用 MemoryStore**
- [ ] 登录后 **regenerate Session ID**（防御 Session Fixation）
- [ ] Cookie 设置 `HttpOnly`, `Secure`（生产环境）, `SameSite=Lax`
- [ ] 重命名默认 Cookie 名称（不用 `connect.sid` 或 `session`）
- [ ] 实现 **Idle Timeout**（30 分钟无操作过期）
- [ ] 实现 **Absolute Timeout**（8 小时绝对过期）
- [ ] Logout 时**服务端销毁 Session**（不仅仅清除客户端 Cookie）
- [ ] 对所有 state-changing 请求实现 **CSRF Token 保护**
- [ ] 密码使用 `bcrypt`（cost ≥ 12）哈希存储
- [ ] Session Secret 使用强随机字符串

### 概念自查

- [ ] 我能解释 Session Auth 和 Basic Auth 的本质区别
- [ ] 我能解释 Session ID 为什么只是一个"取物票"而不包含用户信息
- [ ] 我能解释 Cookie 的 `HttpOnly`, `Secure`, `SameSite` 分别防御什么攻击
- [ ] 我能画出 Login → Session 创建 → Cookie → 请求验证 → Logout 的完整流程
- [ ] 我能解释 Session Fixation 攻击和 Session ID Regeneration 的防御原理
- [ ] 我能解释 CSRF 攻击原理以及为什么 CSRF Token 能防御它
- [ ] 我能解释为什么生产环境不能用 MemoryStore（三个原因）
- [ ] 我能用 `redis-cli` 查看、检查和删除 Session
- [ ] 我理解 Passport 的 `serializeUser` / `deserializeUser` 流程
- [ ] 我知道 Idle Timeout 和 Absolute Timeout 的区别以及为什么两者都需要

---

## 下一步

完成本 Module 后，进入 [Module 03 — API Keys](../03-api-keys/README.md)。

API Key 是认证模型从"凭证型"过渡到"无状态令牌型"的第一步：

1. **标识应用而非用户** — API Key 代表的是一个应用程序/开发者，不是一个终端用户
2. **无状态** — 服务端不需要维护 Session，每个请求都携带 Key 做独立验证
3. **为 JWT (Module 04) 做铺垫** — JWT 把"无状态"理念推向极致，Token 自包含所有验证所需的信息

---

## 参考资料

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [express-session Documentation](https://expressjs.com/en/resources/middleware/session.html)
- [connect-redis GitHub](https://github.com/tj/connect-redis) — v9 API 和迁移说明
- [Flask-Session Documentation](https://flask-session.readthedocs.io/)
- [Flask-WTF CSRF Protection](https://flask-wtf.readthedocs.io/en/latest/csrf/)
- [Passport.js — passport-local](https://www.passportjs.org/packages/passport-local/)
- [Passport.js v0.6.0 — Session Fixation Fix](https://medium.com/passportjs/fixing-session-fixation-b2b68619c51d)
- [csrf-sync npm](https://www.npmjs.com/package/csrf-sync) — csurf 的推荐替代（Synchronizer Token）
- [csrf-csrf npm](https://www.npmjs.com/package/csrf-csrf) — csurf 的推荐替代（Double Submit Cookie）
