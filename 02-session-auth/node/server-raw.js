// server-raw.js — 手动实现 Session Auth，不依赖 Passport
import express from 'express';
import session from 'express-session';
import { RedisStore } from 'connect-redis';
import { createClient } from 'redis';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json()); // 解析 JSON 请求体
const PORT = 3000;

// ============================================
// 1. 连接 Redis
// ============================================
const redisClient = createClient({ url: 'redis://host.docker.internal:6379' });
redisClient.connect().catch(console.error);

redisClient.on('connect', () => console.log('Redis connected'));
redisClient.on('error', (err) => console.error('Redis error:', err));

// ============================================
// 2. 配置 Session Middleware
// ============================================
const redisStore = new RedisStore({
    client: redisClient,
    prefix: 'sess:',  // Redis 中 key 的前缀
});

app.use(session({
    store: redisStore,
    secret: 'change-me-to-a-strong-random-string', // 用于签名 Session ID Cookie
    name: 'sessionId',        // 重命名 Cookie（默认是 "connect.sid"）
    resave: false,            // 没有修改时不重新保存（必须显式设置）
    saveUninitialized: false, // 未登录的用户不创建 Session（必须显式设置）
    cookie: {
        httpOnly: true,         // 阻止 JavaScript 访问 Cookie
        secure: false,          // 开发环境用 false（生产环境改为 true）
        sameSite: 'lax',        // CSRF 纵深防御
        maxAge: 1000 * 60 * 30, // 30 分钟 idle timeout
    },
}));

// ============================================
// 3. 模拟用户数据库（生产环境用真实数据库）
// ============================================
const users = {};

async function initUsers() {
    const SALT_ROUNDS = 12;
    users['admin@example.com'] = {
        id: 1,
        email: 'admin@example.com',
        passwordHash: await bcrypt.hash('secret123', SALT_ROUNDS),
        role: 'admin',
    };
    users['viewer@example.com'] = {
        id: 2,
        email: 'viewer@example.com',
        passwordHash: await bcrypt.hash('readonly456', SALT_ROUNDS),
        role: 'viewer',
    };
    console.log('Users initialized');
}

// ============================================
// 4. 认证 Middleware — 检查 Session 是否有效
// ============================================
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated. Please login first.' });
    }
    next();
};

// ============================================
// 5. Absolute Timeout Middleware
// ============================================
const ABSOLUTE_TIMEOUT = 8 * 60 * 60 * 1000; // 8 小时

const checkAbsoluteTimeout = (req, res, next) => {
    if (req.session.createdAt) {
        const elapsed = Date.now() - req.session.createdAt;
        if (elapsed > ABSOLUTE_TIMEOUT) {
            return req.session.destroy((err) => {
                if (err) return next(err);
                res.clearCookie('sessionId');
                return res.status(401).json({ error: 'Session expired (absolute timeout)' });
            });
        }
    }
    next();
};

app.use(checkAbsoluteTimeout);

// ============================================
// 6. 路由
// ============================================

// 公开端点
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 登录
app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    const user = users[email];

    // Timing Attack 防御：即使用户不存在也执行 bcrypt.compare
    const dummyHash = '$2b$12$LJ3m4ys3Lk0TSwHjpF2gT.UzIR3WH9CPNRGK/7e7e3jY3CSJiXZ2e';
    const isMatch = await bcrypt.compare(password, user?.passwordHash || dummyHash);

    if (!user || !isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ★ 关键：登录成功后 regenerate Session ID，防御 Session Fixation
    req.session.regenerate((err) => {
        if (err) return next(err);

        // 在新 Session 中存储用户信息
        req.session.userId = user.id;
        req.session.email = user.email;
        req.session.role = user.role;
        req.session.createdAt = Date.now(); // 用于 Absolute Timeout

        // 显式保存（确保在发送响应之前 Session 已写入 Redis）
        req.session.save((err) => {
            if (err) return next(err);
            console.log(`Login: ${email}, new session: ${req.session.id} `);
            res.json({
                message: 'Login successful',
                user: { id: user.id, email: user.email, role: user.role },
            });
        });
    });
});

// 登出
app.post('/logout', (req, res, next) => {
    const sessionId = req.session.id;

    // ★ 关键：服务端销毁 Session（不仅仅是删除客户端 Cookie）
    req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie('sessionId'); // 清除客户端的 Cookie
        console.log(`Logout: session ${sessionId} destroyed`);
        res.json({ message: 'Logged out successfully' });
    });
});

// 受保护端点 — 查看个人信息
app.get('/api/profile', requireAuth, (req, res) => {
    res.json({
        userId: req.session.userId,
        email: req.session.email,
        role: req.session.role,
        sessionCreatedAt: new Date(req.session.createdAt).toISOString(),
    });
});

// 受保护端点 — 模拟笔记 CRUD
app.get('/api/notes', requireAuth, (req, res) => {
    res.json({
        notes: [
            { id: 1, title: 'Learn Session Auth', body: 'Understand cookies and sessions' },
            { id: 2, title: 'Redis as Session Store', body: 'Never use MemoryStore in production' },
        ],
        user: req.session.email,
    });
});

// 查看当前 Session 信息（调试用）
app.get('/debug/session', requireAuth, (req, res) => {
    res.json({
        sessionId: req.session.id,
        cookie: req.session.cookie,
        data: {
            userId: req.session.userId,
            email: req.session.email,
            role: req.session.role,
            createdAt: req.session.createdAt,
        },
    });
});
import { csrfSync } from 'csrf-sync';

// ============================================
// CSRF 配置
// ============================================
const {
    generateToken,                 // 生成 CSRF Token
    csrfSynchronisedProtection,    // 验证 CSRF Token 的 Middleware
    invalidCsrfTokenError,         // Token 无效时的错误对象
} = csrfSync({
    getTokenFromRequest: (req) => req.headers['x-csrf-token'], // 从 Header 获取 Token
});

// 获取 CSRF Token 的端点（登录后调用）
app.get('/csrf-token', (req, res) => {
    const token = generateToken(req, res);
    res.json({ csrfToken: token });
});

// 对 state-changing 请求应用 CSRF 保护
// csrf-sync 自动跳过 GET, HEAD, OPTIONS 请求
app.post('/api/notes', requireAuth, csrfSynchronisedProtection, (req, res) => {
    const { title, body } = req.body;
    res.status(201).json({ message: 'Note created', note: { title, body } });
});

app.post('/logout', csrfSynchronisedProtection, (req, res, next) => {
    req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie('sessionId');
        res.json({ message: 'Logged out' });
    });
});

// CSRF 错误处理
app.use((err, req, res, next) => {
    if (err === invalidCsrfTokenError) {
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    next(err);
});

// ============================================
// 7. 启动服务器
// ============================================
initUsers().then(() => {
    app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
});