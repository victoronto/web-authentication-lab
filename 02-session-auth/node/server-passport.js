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
const redisClient = createClient({ url: 'redis://192.168.215.1:6379' });
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
