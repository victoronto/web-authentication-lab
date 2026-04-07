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