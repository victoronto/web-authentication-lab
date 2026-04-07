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