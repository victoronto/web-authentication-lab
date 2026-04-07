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