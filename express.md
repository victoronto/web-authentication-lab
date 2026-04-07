what is this express package? why we need it in this course3:02 PM这个问题很直接，不需要做 research，我可以直接解释。

Express 是什么？
Express 是 Node.js 最主流的 Web Framework。Node.js 本身有内置的 http 模块可以创建 HTTP 服务器，但非常底层——你需要自己解析 URL、处理路由、读取 Header、组装响应。Express 在这个基础上提供了一层简洁的抽象。
类比 Python 的话：Express 之于 Node.js ≈ Flask 之于 Python。
javascript// 没有 Express（纯 Node.js http 模块）— 非常繁琐
const http = require('http');
const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  } else if (req.method === 'GET' && req.url === '/api/data') {
    // 手动解析 Authorization header...
    // 手动处理 401 响应...
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

// 有 Express — 简洁直观
const express = require('express');
const app = express();

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/data', basicAuth, (req, res) => res.json({ data: '...' }));
为什么这门课需要它？
Express 提供了三个对学习 Authentication 至关重要的能力：
1. Routing — app.get('/path', handler) 让你轻松定义公开端点和受保护端点，这样你可以专注于认证逻辑本身，而不是 URL 解析。
2. Middleware — 这是 Express 的核心概念，也是整个课程的关键模式。Middleware 是一个函数，在请求到达路由之前拦截并处理它：
javascript//         这就是 middleware ↓
app.get('/api/data', basicAuth, (req, res) => { ... });
//                      |
//    请求先经过 basicAuth 检查
//    通过 → 调用 next() 进入路由
//    失败 → 返回 401，请求到不了路由
Basic Auth、Session Auth、JWT 验证、OAuth Token 验证——课程中每一种认证机制都是作为 Middleware 实现的。理解 Middleware 模式，后面所有 Module 都会很顺畅。
3. req / res 对象 — Express 把 HTTP 请求和响应封装成了方便操作的对象。req.headers.authorization 直接拿到 Header，res.status(401).json(...) 一行返回错误响应。
会贯穿整个课程吗？
是的。Express 是你所有 Node.js 实现的基础框架：
ModuleExpress 的角色01 Basic Auth自定义 Middleware 解析 Authorization Header02 Session Authexpress-session Middleware 管理 Cookie04 JWTJWT 验证 Middleware05 OAuth 2.0Passport.js Strategy（Passport 本身就是 Express Middleware）06 OIDCexpress-openid-connect Middleware07 SSOpassport-saml Middleware
Python 那边的对应就是 Flask——同样的角色，同样的 Middleware 模式（Flask 里叫 decorator），两边对照着学会加深你对认证机制本身（而不是框架）的理解。