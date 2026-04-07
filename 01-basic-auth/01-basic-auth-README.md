# Module 01 — Basic Authentication

> 从最简单的认证方案开始，理解 HTTP 认证的底层机制。

---

## 学习目标

完成本 Module 后，你将能够：

- 理解 HTTP Basic Auth 的完整 Challenge-Response 流程
- 手动构造和解码 `Authorization` Header
- 用 Node.js 从零实现 Basic Auth Middleware（不依赖任何库）
- 用 Passport.js 重构，理解抽象层带来的差异
- 用 Python Flask-HTTPAuth 实现同样的功能
- 理解并演示 Base64 编码不等于加密
- 理解 Timing Attack 并用 `crypto.timingSafeEqual` 防御
- 用 `curl` 和 `HTTPie` 从命令行测试认证端点

---

## 前置准备

```bash
# 确保你在 repo 的 Module 01 目录
cd web-auth-learning/01-basic-auth

# 创建子目录
mkdir -p node python tests
```

---

## Part 1：理论 — HTTP Basic Auth 协议机制

### 这是什么？

HTTP Basic Authentication 是最简单的 HTTP 认证方案，定义于 **RFC 7617**（2015 年 9 月，取代了旧的 RFC 2617）。它在每个请求的 `Authorization` Header 中发送 Base64 编码的 `username:password`。

### 我们学到什么？

这是所有 Web Authentication 的起点。通过学习 Basic Auth，你会理解：

- HTTP 层面的认证是如何工作的（Header-based）
- Challenge-Response 模式（几乎所有认证方案的基础）
- 为什么"编码"和"加密"是完全不同的两件事
- 为什么 HTTPS 不是可选的，而是强制性的

### Challenge-Response 流程

```
CLIENT                                          SERVER
  |                                               |
  |  1) GET /protected HTTP/1.1                   |
  |  Host: example.com                            |
  |  （没有 Authorization Header）                  |
  |---------------------------------------------->|
  |                                               |
  |  2) HTTP/1.1 401 Unauthorized                 |
  |  WWW-Authenticate: Basic realm="MyApp"        |
  |<----------------------------------------------|
  |                                               |
  |  （浏览器弹出原生登录对话框 /                     |
  |   CLI 工具在下次请求中附带凭证）                  |
  |                                               |
  |  3) GET /protected HTTP/1.1                   |
  |  Authorization: Basic YWRtaW46c2VjcmV0MTIz   |
  |---------------------------------------------->|
  |                                               |
  |  4a) 200 OK          （凭证有效）               |
  |  4b) 401 Unauthorized （凭证无效，重试）          |
  |  4c) 403 Forbidden    （凭证有效但无权限）        |
  |<----------------------------------------------|
```

**关键规则（来自 RFC 7235）：**

- 服务端的每个 `401` 响应**必须**包含 `WWW-Authenticate` Header
- `realm` 参数是必需的，描述受保护区域的名称
- RFC 7617 新增了可选的 `charset="UTF-8"` 参数

### Authorization Header 的构成

格式：`Basic <base64(userid:password)>`

服务端收到后：

1. 提取 `Basic ` 后面的部分
2. Base64 解码
3. 在**第一个**冒号处分割（密码中可以包含冒号）
4. 验证 username 和 password

### Base64 编码过程（动手验证）

以 RFC 的经典示例为例：username = `Aladdin`，password = `open sesame`

1. 用冒号连接：`Aladdin:open sesame`
2. 转换为 UTF-8 字节
3. 按 Base64 规则编码
4. 结果：`QWxhZGRpbjpvcGVuIHNlc2FtZQ==`

**现在在你的 terminal 里验证：**

```bash
# 编码
echo -n "Aladdin:open sesame" | base64
# 输出: QWxhZGRpbjpvcGVuIHNlc2FtZQ==

# 解码（证明 Base64 是可逆的）
echo "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 -d
# 输出: Aladdin:open sesame
```

> **关键认知：** Base64 是**编码**（encoding），不是**加密**（encryption）。任何人都能解码。这意味着如果不使用 HTTPS，凭证就是明文传输的。

---

## Part 2：动手实践 — Node.js 实现

### Step 1：初始化项目

```bash
cd 01-basic-auth/node
npm init -y
npm install express
```

### Step 2：从零构建 Raw Middleware（不用任何认证库）

**为什么先不用库？** 理解底层机制比直接用抽象层更重要。你需要亲手解析 `Authorization` Header，才能真正理解 Basic Auth 的工作原理。

创建 `server-raw.js`：

```javascript
// server-raw.js — 手动实现 Basic Auth，不依赖任何认证库
const express = require('express');
const app = express();
const PORT = 3000;

// ============================================
// 模拟用户数据库（明文密码 — 后面会改成 bcrypt）
// ============================================
const USERS = {
  admin: 'secret123',
  viewer: 'readonly456'
};

// ============================================
// Basic Auth Middleware — 核心逻辑
// ============================================
const basicAuth = (req, res, next) => {
  // Step 1: 检查 Authorization Header 是否存在
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    // 必须返回 WWW-Authenticate Header（RFC 7235 要求）
    res.set('WWW-Authenticate', 'Basic realm="My Protected API"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Step 2: 提取并解码 Base64 字符串
  const base64Credentials = authHeader.split(' ')[1];
  const decoded = Buffer.from(base64Credentials, 'base64').toString('utf8');

  // Step 3: 在第一个冒号处分割（密码可能包含冒号！）
  // 错误写法: decoded.split(':') — 这会在所有冒号处分割
  // 正确写法: 用 indexOf 找到第一个冒号的位置
  const separatorIndex = decoded.indexOf(':');

  if (separatorIndex === -1) {
    res.set('WWW-Authenticate', 'Basic realm="My Protected API"');
    return res.status(401).json({ error: 'Malformed credentials' });
  }

  const username = decoded.substring(0, separatorIndex);
  const password = decoded.substring(separatorIndex + 1);

  // Step 4: 验证凭证
  if (USERS[username] && USERS[username] === password) {
    req.user = { username };
    next();
  } else {
    res.set('WWW-Authenticate', 'Basic realm="My Protected API"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
};

// ============================================
// 路由
// ============================================

// 公开端点 — 不需要认证
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 受保护端点 — 需要 Basic Auth
app.get('/api/data', basicAuth, (req, res) => {
  res.json({
    message: `Hello, ${req.user.username}!`,
    data: ['item1', 'item2', 'item3']
  });
});

app.get('/admin', basicAuth, (req, res) => {
  res.json({ message: 'Admin area', user: req.user.username });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
```

### Step 3：运行并测试

```bash
node server-raw.js
```

**打开另一个 terminal，用 curl 测试：**

```bash
# 测试 1: 公开端点（不需要认证）
curl http://localhost:3000/health
# 期望: {"status":"ok","timestamp":"..."}

# 测试 2: 未认证访问受保护端点
curl -i http://localhost:3000/api/data
# 期望: HTTP/1.1 401 Unauthorized
# 期望: WWW-Authenticate: Basic realm="My Protected API"
# -i 参数显示 Response Header，注意观察 WWW-Authenticate

# 测试 3: 使用 curl -u 快捷方式认证
curl -u admin:secret123 http://localhost:3000/api/data
# 期望: {"message":"Hello, admin!","data":["item1","item2","item3"]}

# 测试 4: 手动构造 Authorization Header
curl -H "Authorization: Basic $(echo -n 'admin:secret123' | base64)" \
  http://localhost:3000/api/data
# 期望: 同上。这证明 -u 只是帮你做了 Base64 编码

# 测试 5: 错误的密码
curl -u admin:wrongpassword http://localhost:3000/api/data
# 期望: 401 + {"error":"Invalid credentials"}

# 测试 6: 详细模式 — 观察完整的 HTTP 请求和响应
curl -v -u admin:secret123 http://localhost:3000/api/data
* Host localhost:3000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:3000...
* Connected to localhost (::1) port 3000
* Server auth using Basic with user 'admin'
> GET /api/data HTTP/1.1
> Host: localhost:3000
> Authorization: Basic YWRtaW46c2VjcmV0MTIz
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Content-Type: application/json; charset=utf-8
< Content-Length: 60
< ETag: W/"3c-k3sc4W4qzr25o3y64k+aS8Y8KaM"
< Date: Tue, 07 Apr 2026 19:23:00 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host localhost left intact
{"message":"Hello, admin!","data":["item1","item2","item3"]}%  
# 观察: > Authorization: Basic YWRtaW46c2VjcmV0MTIz
curl -v 的输出用三种前缀符号区分不同类型的信息：
*（星号）— curl 自身的状态信息
* Host localhost:3000 was resolved.
* IPv6: ::1
* Connected to localhost (::1) port 3000
* Server auth using Basic with user 'admin'
这些是 curl 告诉你它在做什么：DNS 解析、建立 TCP 连接、使用什么认证方式。这些信息不是 HTTP 协议的一部分，是 curl 作为工具的诊断日志。
>（大于号）— 你发出去的 HTTP Request
> GET /api/data HTTP/1.1
> Host: localhost:3000
> Authorization: Basic YWRtaW46c2VjcmV0MTIz
> User-Agent: curl/8.7.1
> Accept: */*
箭头朝右 → 数据从你的 MacBook 流向服务器。这就是 Module 01 里讲的 Challenge-Response 流程中第 3 步：客户端发送带 Authorization Header 的请求。你可以看到 curl -u admin:secret123 被自动转换成了 Authorization: Basic YWRtaW46c2VjcmV0MTIz。
<（小于号）— 服务器返回的 HTTP Response
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=utf-8
< Content-Length: 60
< Date: Tue, 07 Apr 2026 19:23:00 GMT
箭头朝左 ← 数据从服务器流回你的 MacBook。200 OK 说明认证成功。如果你用错误的密码，这里会看到 < HTTP/1.1 401 Unauthorized 和 < WWW-Authenticate: Basic realm="My Protected API"。
简单记忆：* = curl 在说话，> = 你发出去的，< = 服务器回来的。

#
# 现在解码这个值:
echo "YWRtaW46c2VjcmV0MTIz" | base64 -d
# 输出: admin:secret123 — 你的密码完全暴露了！
```

### 我们学到了什么？

- `curl -u user:pass` 只是帮你做了 Base64 编码并加上 `Authorization: Basic ...` Header
- 用 `curl -v` 可以看到完整的 HTTP 交互过程，包括 Challenge（`WWW-Authenticate`）和 Response（`Authorization`）
- Base64 编码后的凭证可以被任何人即时解码，**这不是加密**

---

### Step 4：添加 bcrypt 密码哈希

**为什么？** 上面的代码用明文存储密码。如果数据库泄露，所有密码直接暴露。`bcrypt` 是一种自适应哈希算法，内置 salt，专门为密码存储设计。

```bash
npm install bcrypt
```

创建 `server-bcrypt.js`：

```javascript
// server-bcrypt.js — 用 bcrypt 哈希密码，不再存储明文
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3001;

// ============================================
// 模拟用户数据库（存储哈希值，不是明文！）
// ============================================
const users = {};

// 启动时生成哈希密码（生产环境中这在用户注册时完成）
async function initUsers() {
  const SALT_ROUNDS = 12; // 每增加 1，计算时间翻倍
  users['admin'] = await bcrypt.hash('secret123', SALT_ROUNDS);
  users['viewer'] = await bcrypt.hash('readonly456', SALT_ROUNDS);

  console.log('Password hashes generated:');
  console.log(`  admin: ${users['admin']}`);
  console.log(`  viewer: ${users['viewer']}`);
  // 观察输出: $2b$12$... — 包含算法版本、cost factor、salt 和 hash
}

// ============================================
// Basic Auth Middleware（使用 bcrypt 验证）
// ============================================
const basicAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Protected Area"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const decoded = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const separatorIndex = decoded.indexOf(':');

  if (separatorIndex === -1) {
    res.set('WWW-Authenticate', 'Basic realm="Protected Area"');
    return res.status(401).json({ error: 'Malformed credentials' });
  }

  const username = decoded.substring(0, separatorIndex);
  const password = decoded.substring(separatorIndex + 1);

  // 关键: 即使用户名不存在，也要执行 bcrypt.compare
  // 这样可以防止通过响应时间差异枚举有效用户名（Timing Attack）
  const storedHash = users[username];
  const dummyHash = '$2b$12$LJ3m4ys3Lk0TSwHjpF2gT.UzIR3WH9CPNRGK/7e7e3jY3CSJiXZ2e';

  const isMatch = await bcrypt.compare(password, storedHash || dummyHash);

  if (storedHash && isMatch) {
    req.user = { username };
    next();
  } else {
    res.set('WWW-Authenticate', 'Basic realm="Protected Area"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
};

// 路由
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/data', basicAuth, (req, res) => {
  res.json({ message: `Hello, ${req.user.username}!` });
});

initUsers().then(() => {
  app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
});
```

### 运行并测试

```bash
node server-bcrypt.js
```

```bash
# 正常认证（跟之前一样）
curl -u admin:secret123 http://localhost:3001/api/data

# 观察服务端控制台输出的 hash 值
# 格式: $2b$12$<22字符salt><31字符hash>
# $2b = bcrypt 算法版本
# $12 = cost factor（2^12 = 4096 次迭代）
```

### 我们学到了什么？

- `bcrypt.hash()` 每次生成的结果都不同（因为内置随机 salt）
- `bcrypt.compare()` 从 hash 值中提取 salt，重新计算后比较
- 即使用户名不存在，也要执行 `bcrypt.compare`（防止通过响应时间差异枚举用户名）
- cost factor 12 意味着 2^12 次迭代，增加暴力破解的成本

- curl 发出的 Authorization: Basic YWRtaW46c2VjcmV0MTIz 无论服务端用不用 bcrypt 都是一模一样的。 bcrypt 根本不影响传输过程。
```text
它们保护的是不同的东西
[客户端] ---Base64 编码的密码---> [网络传输] ---> [服务端] ---> [数据库]
              ↑                      ↑              ↑            ↑
          HTTPS 保护这里         HTTPS 保护这里    bcrypt 保护这里
HTTPS/TLS 保护的是传输中的密码——防止网络上的中间人截获凭证。
bcrypt 保护的是存储中的密码——防止数据库泄露后密码被还原。
这是两个完全不同的威胁场景：
威胁没有 HTTPS没有 bcrypt网络嗅探攻击者截获 Base64，立即解码得到密码bcrypt 无法帮你，密码在传输中已经暴露数据库泄露HTTPS 无法帮你，密码已经在数据库里了攻击者拿到的是 hash，无法还原成原始密码
具体场景
假设有人拿到了你的数据库备份：
没有 bcrypt（明文存储）：
数据库内容: { "admin": "secret123" }
攻击者: 直接拿到密码，马上能登录
有 bcrypt：
数据库内容: { "admin": "$2b$12$LJ3m4ys3Lk0T..." }
攻击者: 拿到的是 hash，要暴力破解
         cost factor 12 意味着每次尝试需要 ~250ms
         一个 8 位复杂密码可能需要数年才能破解
为什么这很现实？
数据库泄露的发生频率远比你想象的高——SQL Injection、备份文件外泄、云存储配置错误、内部人员泄露。如果密码是明文存储的，一次泄露就等于所有用户的密码全部暴露。更严重的是，很多用户在多个网站使用相同密码（credential stuffing 攻击）。
所以两者缺一不可

HTTPS — 保护传输过程（Module 01 的 Base64 不是加密，必须靠 HTTPS）
bcrypt — 保护存储层（即使数据库被拖库，密码也无法被还原）

这就像你家的安全：HTTPS 是门锁（防止有人闯入），bcrypt 是保险箱（即使有人闯入了，也拿不到贵重物品）。两层防御保护的是不同环节，缺了任何一层都有风险。
```
---

### Step 5：用 Passport.js 重构

**为什么？** 对比手动实现和使用框架的差异。Passport.js 是 Node.js 生态中最主流的认证中间件，支持 500+ 种认证策略（Strategy）。这里我们用 `passport-http` 提供的 `BasicStrategy`。

```bash
npm install passport passport-http
```

创建 `server-passport.js`：

```javascript
// server-passport.js — 用 Passport.js BasicStrategy
const express = require('express');
const passport = require('passport');
const { BasicStrategy } = require('passport-http');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3002;

const users = {};

async function initUsers() {
  users['admin'] = await bcrypt.hash('secret123', 12);
  users['viewer'] = await bcrypt.hash('readonly456', 12);
}

// ============================================
// 配置 Passport BasicStrategy
// ============================================
// Passport 帮你处理了:
//   - 解析 Authorization Header
//   - Base64 解码
//   - 在第一个冒号处分割
//   - 返回 401 + WWW-Authenticate Header
// 你只需要写验证逻辑
passport.use(new BasicStrategy(async (userid, password, done) => {
  try {
    const storedHash = users[userid];
    const dummyHash = '$2b$12$LJ3m4ys3Lk0TSwHjpF2gT.UzIR3WH9CPNRGK/7e7e3jY3CSJiXZ2e';

    const isMatch = await bcrypt.compare(password, storedHash || dummyHash);

    if (storedHash && isMatch) {
      return done(null, { id: userid, username: userid });
    }
    return done(null, false); // 验证失败，Passport 自动返回 401
  } catch (err) {
    return done(err);
  }
}));

app.use(passport.initialize());

// 路由
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// session: false — Basic Auth 每次请求都发送凭证，不需要 Session
app.get('/api/data',
  passport.authenticate('basic', { session: false }),
  (req, res) => {
    res.json({ message: `Hello, ${req.user.username}!` });
  }
);

initUsers().then(() => {
  app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
});
```

### 我们学到了什么？

对比三种实现方式：

| 对比维度 | Raw Middleware | bcrypt 版本 | Passport.js |
|---------|---------------|-------------|-------------|
| Header 解析 | 手动 `Buffer.from` + `indexOf` | 手动 | Passport 自动处理 |
| `WWW-Authenticate` | 手动设置 | 手动设置 | Passport 自动返回 |
| 密码验证 | 明文比较 `===` | `bcrypt.compare()` | `bcrypt.compare()` |
| 可扩展性 | 单一用途 | 单一用途 | 可切换 Strategy（OAuth, JWT 等） |
| 代码量 | 最多 | 中等 | 最少 |

**核心收获：** 框架帮你处理了协议层的机械性工作（Header 解析、401 响应），但你必须先理解底层机制，才能知道框架在做什么。

---

## Part 3：动手实践 — Python 实现

### Step 1：初始化项目

```bash
cd 01-basic-auth/python
python3 -m venv venv
source venv/bin/activate
pip install Flask Flask-HTTPAuth
```

### Step 2：用 Flask-HTTPAuth 实现

创建 `app.py`：

```python
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
    app.run(debug=True, port=5000)
```

### Step 3：运行并测试

```bash
python app.py
```

```bash
# 用 curl 测试
curl -u admin:secret123 http://localhost:5000/api/data

# 用 HTTPie 测试（更简洁的语法）
http -a admin:secret123 GET http://localhost:5000/api/data
```

### Step 4：用 Python requests 作为客户端测试

创建 `test_client.py`：

```python
# test_client.py — 用 requests 库作为 HTTP 客户端
import requests
from requests.auth import HTTPBasicAuth

BASE_URL = "http://localhost:5000"

# 方式 1: 使用 HTTPBasicAuth 类
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=HTTPBasicAuth("admin", "secret123"))
print(f"Status: {resp.status_code}")
print(f"Body: {resp.json()}")

# 方式 2: 元组简写（效果完全相同）
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=("admin", "secret123"))
print(f"Body: {resp.json()}")

# 查看实际发送的 Authorization Header
print(f"Sent header: {resp.request.headers['Authorization']}")
# 输出: Basic YWRtaW46c2VjcmV0MTIz

# 验证: 解码这个 Base64 值
import base64
decoded = base64.b64decode("YWRtaW46c2VjcmV0MTIz").decode()
print(f"Decoded: {decoded}")
# 输出: admin:secret123

# 测试认证失败的情况
resp = requests.get(f"{BASE_URL}/api/data",
                    auth=("admin", "wrongpassword"))
print(f"Failed status: {resp.status_code}")  # 401
print(f"Failed body: {resp.json()}")
```

```bash
python test_client.py
```

### 我们学到了什么？

- Python `requests` 的 `auth=("user", "pass")` 元组简写等同于 `auth=HTTPBasicAuth("user", "pass")`
- `resp.request.headers` 可以查看**实际发送**的 HTTP Header，非常有用的调试技巧
- `werkzeug.security` 的 `generate_password_hash` 在 Werkzeug 2.3+ 默认使用 **scrypt** 算法（不是旧教程中的 `pbkdf2:sha256`）
- Flask-HTTPAuth 的三个装饰器模式：`@auth.verify_password`（验证逻辑）、`@auth.login_required`（保护路由）、`@auth.error_handler`（自定义错误响应）

---

## Part 4：安全漏洞演示

### 演示 1：Base64 不是加密

这是 Module 01 最重要的认知。在四个环境中验证：

**Terminal（macOS）：**

```bash
# 编码
echo -n "admin:secret123" | base64
# YWRtaW46c2VjcmV0MTIz

# 解码 — 瞬间还原
echo "YWRtaW46c2VjcmV0MTIz" | base64 -d
# admin:secret123
```

**Node.js：**

```javascript
// 编码
Buffer.from('admin:secret123').toString('base64')
// 'YWRtaW46c2VjcmV0MTIz'

// 解码
Buffer.from('YWRtaW46c2VjcmV0MTIz', 'base64').toString()
// 'admin:secret123'
```

**Python：**

```python
import base64

# 编码
base64.b64encode(b'admin:secret123').decode()
# 'YWRtaW46c2VjcmV0MTIz'

# 解码
base64.b64decode('YWRtaW46c2VjcmV0MTIz').decode()
# 'admin:secret123'
```

> **结论：** 任何截获 `Authorization` Header 的人——恶意 Wi-Fi 热点、网络嗅探器、配置错误的代理——都能立即读取你的凭证。这就是为什么 **HTTPS 是强制性的，不是可选的**。

### 演示 2：Timing Attack 与防御

**什么是 Timing Attack？**

普通的 `===` 字符串比较在遇到第一个不匹配的字符时就会返回 `false`。攻击者通过发送大量请求并统计响应时间的微小差异，可以逐字符推断出正确的值——把暴力破解的复杂度从指数级降低到线性级。

**错误写法（有漏洞）：**

```javascript
// ❌ 危险: === 会短路返回
if (apiKey === storedApiKey) { /* ... */ }
```

**正确写法（时间恒定比较）：**

```javascript
const crypto = require('crypto');

// ✅ 安全: 无论是否匹配，比较时间都相同
function timingSafeCompare(a, b) {
  // crypto.timingSafeEqual 要求两个 Buffer 长度相同
  // 先用 SHA-256 哈希来统一长度
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// 使用时：两个比较都要执行，不要提前返回
const usernameMatch = timingSafeCompare(username, 'admin');
const passwordMatch = timingSafeCompare(password, 'secret123');
if (usernameMatch && passwordMatch) { /* 授权 */ }
```

> **注意：** `bcrypt.compare()` 内部已经是 timing-safe 的（因为它无论匹配与否都会执行完整的 bcrypt 运算）。`crypto.timingSafeEqual` 主要用于直接比较字符串/Token/API Key 的场景。

### 演示 3：浏览器凭证缓存（No Logout 问题）

浏览器在 Basic Auth 成功后会**缓存凭证在内存中**，自动附加到同一 authentication scope 内的所有后续请求。

**关键问题：** HTTP 协议中没有定义任何 Header 或 Status Code 来告诉浏览器"忘记凭证"。RFC 7235 根本没有定义 Logout 机制。

**唯一可靠的"登出"方式是关闭整个浏览器。**

这一点使得 Basic Auth **不适合**任何公开面向用户的 Web 应用（用户可能共享设备）。

### 演示 4：暴力破解防护

由于 Basic Auth 在每个请求中都传输凭证，Rate Limiting 是必需的。

**Node.js 方案：**

```bash
npm install express-rate-limit
```

```javascript
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 分钟
  max: 5,                    // 每个 IP 最多 5 次失败尝试
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// 只对需要认证的路由应用
app.use('/api', authLimiter);
app.use('/admin', authLimiter);
```

**OWASP 建议：** 实现**双键限制**——同时按 username 和 IP 地址限制尝试次数。使用渐进式延迟（5 分钟 → 15 分钟 → 1 小时），而不是永久锁定（永久锁定会被用于 DoS 攻击）。

---

## Part 5：测试工具速查

### curl 命令

```bash
# 基本认证（curl 自动编码）
curl -u admin:secret123 http://localhost:3000/api/data

# 手动构造 Header
curl -H "Authorization: Basic $(echo -n 'admin:secret123' | base64)" \
  http://localhost:3000/api/data

# 详细模式 — 查看完整 HTTP 请求和响应 Header
curl -v -u admin:secret123 http://localhost:3000/api/data

# 交互式输入密码（省略冒号后的部分）
curl -u admin http://localhost:3000/api/data

# 解码捕获到的 Base64 字符串
echo "YWRtaW46c2VjcmV0MTIz" | base64 -d
```

### HTTPie 命令

```bash
# 默认就是 Basic Auth
http -a admin:secret123 GET http://localhost:3000/api/data

# 显式指定认证类型
http --auth-type basic -a admin:secret123 GET :3000/api/data

# 详细输出（彩色高亮 Header + Body）
http -v -a admin:secret123 :3000/api/data

# 持久化 Session（跨请求复用认证）
http --session=dev -a admin:secret123 :3000/api/data
http --session=dev :3000/api/data    # 不需要再次输入凭证
```

> **提示：** HTTPie 的 `:3000` 是 `localhost:3000` 的简写，加上彩色输出，非常适合日常 API 测试。

---

## Part 6：适用场景与局限性

### Basic Auth 适用于

- Staging 环境的访问门禁
- VPN 后面的内部工具
- 机器对机器（M2M）通信（在 HTTPS 上）
- CI/CD Pipeline 认证
- 快速原型开发

### Basic Auth 不适用于

- 任何公开面向用户的 Web 应用（没有 Logout 机制）
- 需要 MFA（多因素认证）的场景
- 需要 CSRF 防护的场景
- 移动应用（凭证管理不便）

### OWASP 的立场

OWASP Authentication Cheat Sheet 不推荐在生产 Web 应用中使用 Basic Auth。它要求的 Session 管理、服务端失效、Logout 能力和 CSRF 防护——这些 Basic Auth 都不支持。

**密码存储优先级（OWASP 推荐）：** Argon2id（首选）→ scrypt → bcrypt（cost ≥ 10）→ PBKDF2。绝不要用裸 MD5、SHA-1 或 SHA-256（没有 key stretching）。

---

## Part 7：模块总结与自查清单

### 安全清单

- [ ] 密码使用 `bcrypt`（Node.js）或 `scrypt`/`generate_password_hash`（Python）哈希存储
- [ ] 强制 HTTPS（所有认证页面和受保护端点）
- [ ] 正确返回 `WWW-Authenticate` Header（RFC 7235 要求）
- [ ] 使用 `crypto.timingSafeEqual` 或 `bcrypt.compare` 做时间恒定比较
- [ ] 即使用户名不存在，也执行密码比较（防止 Timing-based 用户名枚举）
- [ ] 实现 Rate Limiting（按 IP 和 username 双键限制）
- [ ] 部署 HSTS Header 防止 SSL Stripping 攻击

### 概念自查

- [ ] 我能解释 `Authorization: Basic xxx` 中的 `xxx` 是怎么来的
- [ ] 我能在 terminal 中手动编码和解码 Base64
- [ ] 我理解为什么 Base64 编码 ≠ 加密
- [ ] 我能解释 Challenge-Response 流程中每一步的 HTTP Header
- [ ] 我理解为什么 `===` 比较有 Timing Attack 风险
- [ ] 我知道 `bcrypt.compare()` 为什么是 timing-safe 的
- [ ] 我能解释为什么 Basic Auth 没有真正的 Logout 机制
- [ ] 我知道 Basic Auth 适合和不适合的使用场景

---

## 下一步

完成本 Module 后，进入 [Module 02 — Session-based Authentication](../02-session-auth/README.md)。

Session Auth 通过在服务端存储会话状态来解决 Basic Auth 的两大核心问题：

1. **不再每次请求都传输凭证** — 凭证只在登录时传输一次，之后用 Session ID Cookie 维持状态
2. **有了真正的 Logout 机制** — 服务端销毁 Session 即可

---

## 参考资料

- [RFC 7617 — The 'Basic' HTTP Authentication Scheme](https://httpwg.org/specs/rfc7617.html)
- [RFC 7235 — Hypertext Transfer Protocol: Authentication](https://httpwg.org/specs/rfc7235.html)
- [MDN Web Docs — HTTP Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Authentication)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Passport.js — passport-http](https://www.passportjs.org/packages/passport-http/)
- [Flask-HTTPAuth Documentation](https://flask-httpauth.readthedocs.io/)
