

'use strict';

const express       = require('express');
const cookieParser  = require('cookie-parser');
const bodyParser    = require('body-parser');
const fs            = require('fs');
const path          = require('path');
const crypto        = require('crypto');
const os            = require('os');
const { exec, execSync, spawn } = require('child_process');
const http          = require('http');
const https         = require('https');
const net           = require('net');
const url           = require('url');
const vm            = require('vm');
const util          = require('util');
const EventEmitter  = require('events');

const CONFIG = {
    PORT: process.env.PORT || 3000,
    SECRET_KEY: 'super-secret-key-12345',             
    JWT_SECRET: 'jwt-secret-do-not-share',               
    ADMIN_PASSWORD: 'admin123',                           
    DB_PASSWORD: 'root:root@localhost',                    
    UPLOAD_DIR: path.join(__dirname, 'uploads'),
    BACKUP_DIR: path.join(__dirname, 'backups'),
    LOG_FILE: path.join(__dirname, 'app.log'),
    MAX_UPLOAD: 50 * 1024 * 1024,
    DEBUG: true,                                          
    ALLOW_REGISTRATION: true,
    VERSION: '1.0.0-vulnerable'
};




const DB = {
    users: [
        {
            id: 1, username: 'admin', password: md5('admin123'),
            email: 'admin@vulnblog.local', role: 'admin', bio: 'I am the admin.',
            balance: 1000000, api_key: 'AKIA-ADMIN-0001', created: '2023-01-01',
            secret_note: 'FLAG{admin_secret_note_1}'
        },
        {
            id: 2, username: 'alice', password: md5('password'),
            email: 'alice@vulnblog.local', role: 'user', bio: 'Hi, I am Alice!',
            balance: 500, api_key: 'AKIA-ALICE-0002', created: '2023-02-15',
            secret_note: 'alice private note'
        },
        {
            id: 3, username: 'bob', password: md5('qwerty'),
            email: 'bob@vulnblog.local', role: 'user', bio: 'Bob here.',
            balance: 120, api_key: 'AKIA-BOB-0003', created: '2023-03-20',
            secret_note: 'bob private note'
        },
        {
            id: 4, username: 'charlie', password: md5('123456'),
            email: 'charlie@vulnblog.local', role: 'moderator', bio: '',
            balance: 0, api_key: 'AKIA-CHARLIE-0004', created: '2023-05-05',
            secret_note: 'mod note'
        }
    ],
    posts: [
        {
            id: 1, author_id: 1, title: 'Welcome to VulnBlog',
            body: 'This is the very first post. Enjoy!',
            tags: 'welcome,news', created: '2023-06-01', views: 42,
            private: false
        },
        {
            id: 2, author_id: 2, title: 'Alice thoughts',
            body: 'Today I learned about XSS. <script>alert(1)</script>',
            tags: 'personal', created: '2023-06-02', views: 10,
            private: false
        },
        {
            id: 3, author_id: 1, title: 'Admin private post',
            body: 'FLAG{private_post_of_admin}',
            tags: 'secret', created: '2023-06-03', views: 1,
            private: true
        }
    ],
    comments: [
        { id: 1, post_id: 1, author_id: 2, body: 'Nice post!', created: '2023-06-01' },
        { id: 2, post_id: 1, author_id: 3, body: 'Agreed.', created: '2023-06-01' }
    ],
    messages: [
        { id: 1, from_id: 1, to_id: 2, subject: 'Hi', body: 'Welcome, Alice', read: false },
        { id: 2, from_id: 2, to_id: 1, subject: 'Thanks', body: 'Thanks admin!', read: true },
        { id: 3, from_id: 1, to_id: 1, subject: 'Note to self', body: 'FLAG{msg_self_1}', read: true }
    ],
    notes: [
        { id: 1, user_id: 1, title: 'Admin note', content: 'FLAG{admin_note_1}' },
        { id: 2, user_id: 2, title: 'Alice note', content: 'buy milk' },
        { id: 3, user_id: 3, title: 'Bob note', content: 'bob diary' }
    ],
    sessions: {}, 
    audit_log: []
};

let NEXT_ID = { users: 5, posts: 4, comments: 3, messages: 4, notes: 4 };

function md5(s) {
    return crypto.createHash('md5').update(String(s)).digest('hex');
}

function weakToken() {
    return md5(Date.now() + ':' + Math.random());
}


function stripSqlComments(sql) {
    return String(sql)
        .replace(/--[^\n]*/g, '')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .trim();
}

function sqlConditionToJs(cond, row) {
    let expr = stripSqlComments(cond);

    expr = expr.replace(/<>/g, '!==');
    expr = expr.replace(/>=/g, '#GE#');
    expr = expr.replace(/<=/g, '#LE#');
    expr = expr.replace(/!=/g, '!==');

    expr = expr.replace(/([^<>=!])=([^=])/g, '$1===$2');
    expr = expr.replace(/#GE#/g, '>=');
    expr = expr.replace(/#LE#/g, '<=');

    expr = expr.replace(/\bAND\b/gi, '&&');
    expr = expr.replace(/\bOR\b/gi, '||');
    expr = expr.replace(/\bNOT\b/gi, '!');

    expr = expr.replace(/(\S+)\s+LIKE\s+('[^']*')/gi, 'matchLike($1, $2)');

    const cols = Object.keys(row);
    for (const col of cols) {
        const re = new RegExp('\\b' + col.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
        expr = expr.replace(re, `row[${JSON.stringify(col)}]`);
    }


    return expr;
}

function matchLike(value, pattern) {
    try {
        const re = new RegExp('^' + String(pattern).replace(/%/g, '.*').replace(/_/g, '.') + '$');
        return re.test(String(value));
    } catch (e) { return false; }
}

function dbSelect(table, columns, where, orderBy, limit) {
    const rows = DB[table] || [];
    const result = [];
    for (const row of rows) {
        let ok = true;
        if (where) {
            const js = sqlConditionToJs(where, row);
            try {
                ok = !!vm.runInNewContext(js, {
                    row,
                    matchLike,
                    Math, Date, String, Number, Boolean
                });
            } catch (e) {
                ok = false;
            }
        }
        if (ok) result.push(JSON.parse(JSON.stringify(row)));
    }

    if (orderBy && /desc/i.test(orderBy)) {
        result.sort((a, b) => (b.id || 0) - (a.id || 0));
    } else if (orderBy) {
        result.sort((a, b) => (a.id || 0) - (b.id || 0));
    }

    if (limit) {
        const n = parseInt(limit, 10);
        if (!isNaN(n) && n >= 0) result.length = Math.min(result.length, n);
    }
    return result;
}

function query(sql) {

    sql = String(sql).trim().replace(/;$/, '');

    const m = /^SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?(?:\s+LIMIT\s+(\d+))?$/i.exec(sql);
    if (!m) throw new Error('SQL parse error: ' + sql);
    const [, cols, table, where, orderBy, limit] = m;
    return dbSelect(table, cols, where, orderBy, limit);
}

function insertRow(table, obj) {
    obj.id = NEXT_ID[table]++ || (obj.id = DB[table].length + 1);
    DB[table].push(obj);
    return obj;
}

function log(line) {
    const entry = `[${new Date().toISOString()}] ${line}\n`;
    try { fs.appendFileSync(CONFIG.LOG_FILE, entry); } catch (e) {}
    if (CONFIG.DEBUG) process.stdout.write(entry);
}

function createSession(user, req) {
    const token = weakToken();                 
    DB.sessions[token] = {
        user_id: user.id,
        username: user.username,
        role: user.role,
        created: Date.now(),
        ip: req.ip,
        ua: req.headers['user-agent'] || '',
    };
    return token;
}

function getSession(req) {
    const t = req.cookies && req.cookies.sid;
    if (!t) return null;
    const s = DB.sessions[t];
    if (!s) return null;

    return s;
}

function currentUser(req) {
    const s = getSession(req);
    if (!s) return null;
    return DB.users.find(u => u.id === s.user_id) || null;
}

app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.text({ limit: '100mb' }));
app.use(bodyParser.raw({ limit: '100mb' }));
app.use(cookieParser());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    if (req.method === 'OPTIONS') return res.end();
    next();
});

app.use((req, res, next) => {
    res.removeHeader('X-Powered-By');
    res.setHeader('X-Powered-By', 'VulnBlog/' + CONFIG.VERSION);
    next();
});

app.use((req, res, next) => {
    log(`${req.method} ${req.url} UA="${req.headers['user-agent'] || ''}" IP=${req.ip}`);
    DB.audit_log.push({
        time: Date.now(),
        method: req.method,
        url: req.url,
        ip: req.ip,
        user: (currentUser(req) || {}).username || 'anon'
    });
    next();
});

app.use('/uploads', express.static(CONFIG.UPLOAD_DIR));
app.use('/static', express.static(path.join(__dirname, 'public')));


function layout(title, body, user) {
    const nav = user
        ? `<span>Привет, <a href="/profile/${user.id}">${user.username}</a> (${user.role})</span>
           <a href="/messages">Сообщения</a>
           <a href="/notes">Заметки</a>
           <a href="/post/new">Новый пост</a>
           ${user.role === 'admin' ? '<a href="/admin">Админка</a>' : ''}
           <a href="/logout">Выход</a>`
        : `<a href="/login">Вход</a> | <a href="/register">Регистрация</a>`;

    return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>${title} — VulnBlog</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:1rem;background:#f8f8f8}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #333;padding-bottom:.5rem;margin-bottom:1rem}
nav a{margin-left:.75rem;text-decoration:none;color:#06c}
.card{background:#fff;border:1px solid #ddd;border-radius:6px;padding:1rem;margin:.75rem 0;box-shadow:0 1px 2px rgba(0,0,0,.05)}
input,textarea{width:100%;padding:.4rem;margin:.2rem 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
button{padding:.4rem .9rem;border:0;background:#06c;color:#fff;border-radius:4px;cursor:pointer}
button.danger{background:#c00}
pre{background:#222;color:#0f0;padding:.6rem;overflow:auto;border-radius:4px}
code{background:#eee;padding:.1rem .3rem;border-radius:3px}
.small{color:#666;font-size:.85rem}
.error{background:#fdd;border:1px solid #f99;padding:.5rem;border-radius:4px}
.ok{background:#dfd;border:1px solid #9f9;padding:.5rem;border-radius:4px}
</style>
</head>
<body>
<header>
  <h1><a href="/" style="text-decoration:none;color:#333">📝 VulnBlog</a></h1>
  <nav>${nav}</nav>
</header>
<main>${body}</main>
<footer class="small" style="margin-top:2rem;border-top:1px solid #ccc;padding-top:.5rem">
  VulnBlog ${CONFIG.VERSION} — намеренно уязвимое приложение. Не используйте в продакшене.
</footer>
</body>
</html>`;
}

function esc(s) {

    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

app.get('/', (req, res) => {
    const user = currentUser(req);
    const posts = DB.posts.filter(p => !p.private);
    const html = posts.map(p => {
        const author = DB.users.find(u => u.id === p.author_id);
        return `<div class="card">
            <h3><a href="/post/${p.id}">${p.title}</a></h3>
            <div class="small">Автор: <a href="/profile/${p.author_id}">${author ? author.username : '?'}</a> · ${p.created} · ${p.views} просмотров</div>
            <p>${p.body}</p>
            <div class="small">Теги: ${p.tags}</div>
        </div>`;
    }).join('');
    res.send(layout('Главная', `<h2>Свежие посты</h2>${html}`, user));
});

app.get('/register', (req, res) => {
    res.send(layout('Регистрация', `
        <h2>Регистрация</h2>
        <form method="post" action="/register">
            <input name="username" placeholder="Логин" required>
            <input name="password" type="password" placeholder="Пароль" required>
            <input name="email" placeholder="Email">
            <textarea name="bio" placeholder="О себе"></textarea>
            <button>Создать аккаунт</button>
        </form>
    `, currentUser(req)));
});

app.post('/register', (req, res) => {
    const body = req.body;
    const username = body.username;
    if (!username || !body.password) {
        return res.status(400).send(layout('Ошибка', '<div class="error">Заполните все поля</div>', null));
    }
    if (DB.users.find(u => u.username === username)) {
        return res.status(400).send(layout('Ошибка', '<div class="error">Пользователь уже существует</div>', null));
    }
    const user = {
        id: NEXT_ID.users++,
        username,
        password: md5(body.password),
        email: body.email || '',
        role: body.role || 'user',                      
        bio: body.bio || '',
        balance: parseInt(body.balance || '0', 10) || 0,
        api_key: 'AKIA-' + md5(username).slice(0, 8),
        created: new Date().toISOString().slice(0, 10),
        secret_note: ''
    };
    DB.users.push(user);
    log(`New user registered: ${username}`);
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    const err = req.query.err ? '<div class="error">Неверные данные</div>' : '';
    res.send(layout('Вход', `
        <h2>Вход</h2>
        ${err}
        <form method="post" action="/login">
            <input name="username" placeholder="Логин" value="${req.query.username || ''}">
            <input name="password" type="password" placeholder="Пароль">
            <button>Войти</button>
        </form>
        <p class="small">Подсказка: попробуйте <code>admin' --</code> в поле логина.</p>
    `, currentUser(req)));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(password || '')}'`;
    log('LOGIN SQL: ' + sql);

    let rows;
    try {
        rows = query(sql);
    } catch (e) {
        return res.status(500).send(layout('Ошибка',
            `<div class="error"><pre>${e.stack}</pre></div>`, null));
    }

    if (!rows || rows.length === 0) {
        return res.redirect('/login?err=1');
    }

    const user = DB.users.find(u => u.id === rows[0].id);
    if (!user) return res.redirect('/login?err=1');

    const token = createSession(user, req);
    res.cookie('sid', token, { path: '/' });            
    res.redirect('/');
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username === 'object' && username !== null) {
        const user = DB.users.find(u => {
            for (const k of Object.keys(username)) {
                if (k === '$ne' && username[k] !== null && u.username !== username[k]) return true;
                if (k === '$gt' && u.username > username[k]) return true;
                if (k === '$regex' && new RegExp(username[k]).test(u.username)) return true;
            }
            return false;
        }) || DB.users[0];
        const token = createSession(user, req);
        return res.json({ ok: true, token, user: { id: user.id, username: user.username, role: user.role } });
    }
    const user = DB.users.find(u => u.username === username && u.password === md5(password || ''));
    if (!user) return res.status(401).json({ ok: false, error: 'invalid credentials' });
    const token = createSession(user, req);
    res.json({ ok: true, token, user: { id: user.id, username: user.username, role: user.role } });
});

function b64url(buf) {
    return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64').toString('utf8');
}
function signJwt(payload) {
    const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const p = b64url(JSON.stringify(payload));
    const sig = b64url(crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(h + '.' + p).digest());
    return h + '.' + p + '.' + sig;
}
function verifyJwt(token) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new Error('bad token');
    const [h, p, s] = parts;
    const header = JSON.parse(b64urlDecode(h));
    if (header.alg === 'none') {
        return JSON.parse(b64urlDecode(p));
    }
    const expected = b64url(crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(h + '.' + p).digest());
    if (s !== expected) throw new Error('bad signature');
    return JSON.parse(b64urlDecode(p));
}

app.get('/api/token', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'auth required' });
    res.json({ token: signJwt({ sub: user.id, username: user.username, role: user.role }) });
});

app.get('/api/me', (req, res) => {
    const auth = req.headers.authorization || '';
    const token = auth.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'no token' });
    try {
        const payload = verifyJwt(token); 
        const user = DB.users.find(u => u.id === payload.sub);
        if (!user) return res.status(404).json({ error: 'user not found' });
        res.json({ user: { ...user, password: undefined } });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.get('/logout', (req, res) => {
    const t = req.cookies.sid;
    if (t) delete DB.sessions[t];
    res.clearCookie('sid');
    res.redirect('/');
});

app.get('/profile/:id', (req, res) => {
    const u = DB.users.find(x => x.id === parseInt(req.params.id, 10));
    if (!u) return res.status(404).send(layout('404', '<div class="error">Нет такого пользователя</div>', currentUser(req)));
    const me = currentUser(req);
    const isMine = me && me.id === u.id;
    const posts = DB.posts.filter(p => p.author_id === u.id && (!p.private || isMine));

    res.send(layout('Профиль ' + u.username, `
        <h2>${u.username}</h2>                              <!-- [VULN-3] XSS -->
        <div class="card">
            <p>${u.bio}</p>                                  <!-- [VULN-3] stored XSS -->
            <p class="small">Email: ${u.email}</p>
            <p class="small">Роль: ${u.role}</p>
            <p class="small">Баланс: ${u.balance}</p>
            <p class="small">API key: <code>${u.api_key}</code></p>
            ${isMine ? `<p class="small">Заметка: ${u.secret_note}</p>` : ''}
            ${isMine ? `<p><a href="/profile/${u.id}/edit">Редактировать</a></p>` : ''}
        </div>
        <h3>Посты</h3>
        ${posts.map(p => `<div class="card"><a href="/post/${p.id}">${p.title}</a></div>`).join('') || '<p>Пока нет.</p>'}
    `, me));
});

app.get('/profile/:id/edit', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const u = DB.users.find(x => x.id === parseInt(req.params.id, 10));
    if (!u) return res.status(404).end('no user');
    res.send(layout('Редактирование', `
        <h2>Редактирование профиля ${u.username}</h2>
        <form method="post" action="/profile/${u.id}/edit">
            <input name="email" value="${esc(u.email)}">
            <textarea name="bio">${esc(u.bio)}</textarea>
            <input name="secret_note" value="${esc(u.secret_note)}">
            <button>Сохранить</button>
        </form>
    `, me));
});

app.post('/profile/:id/edit', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const u = DB.users.find(x => x.id === parseInt(req.params.id, 10));
    if (!u) return res.status(404).end('no user');
    for (const k of Object.keys(req.body)) {
        u[k] = req.body[k];
    }
    res.redirect('/profile/' + u.id);
});

app.get('/post/new', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    res.send(layout('Новый пост', `
        <h2>Новый пост</h2>
        <form method="post" action="/post/new">
            <input name="title" placeholder="Заголовок">
            <textarea name="body" rows="8" placeholder="Текст"></textarea>
            <input name="tags" placeholder="теги через запятую">
            <label><input type="checkbox" name="private" value="1"> приватный</label>
            <button>Опубликовать</button>
        </form>
    `, me));
});

app.post('/post/new', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const p = insertRow('posts', {
        author_id: me.id,
        title: req.body.title || '(без названия)',
        body: req.body.body || '',     
        tags: req.body.tags || '',
        private: !!req.body.private,
        created: new Date().toISOString().slice(0, 10),
        views: 0
    });
    res.redirect('/post/' + p.id);
});

app.get('/post/:id', (req, res) => {
    const p = DB.posts.find(x => x.id === parseInt(req.params.id, 10));
    if (!p) return res.status(404).send(layout('404', '<div class="error">Пост не найден</div>', currentUser(req)));
    p.views++;
    const me = currentUser(req);
    if (p.private && (!me || (me.id !== p.author_id && me.role !== 'admin'))) {
        return res.status(403).send(layout('403', '<div class="error">Приватный пост</div>', me));
    }
    const author = DB.users.find(u => u.id === p.author_id);
    const comments = DB.comments.filter(c => c.post_id === p.id);

    res.send(layout(p.title, `
        <h2>${p.title}</h2>
        <div class="small">Автор: <a href="/profile/${p.author_id}">${author ? author.username : '?'}</a> · ${p.created} · ${p.views} просмотров</div>
        <div class="card">${p.body}</div>                     <!-- [VULN-3] stored XSS -->
        <div class="small">Теги: ${p.tags}</div>
        ${me && (me.id === p.author_id || me.role === 'admin')
            ? `<p><a href="/post/${p.id}/edit">Ред.</a> | <a href="/post/${p.id}/delete">Удалить</a></p>` : ''}
        <h3>Комментарии</h3>
        ${comments.map(c => {
            const a = DB.users.find(u => u.id === c.author_id);
            return `<div class="card"><b>${a ? a.username : '?'}</b> <span class="small">${c.created}</span><p>${c.body}</p></div>`;
        }).join('') || '<p>Нет комментариев.</p>'}
        ${me ? `<form method="post" action="/post/${p.id}/comment">
            <textarea name="body" placeholder="Ваш комментарий"></textarea>
            <button>Отправить</button>
        </form>` : '<p><a href="/login">Войдите</a>, чтобы комментировать.</p>'}
    `, me));
});

app.post('/post/:id/comment', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const pid = parseInt(req.params.id, 10);
    insertRow('comments', {
        post_id: pid,
        author_id: me.id,
        body: req.body.body || '',   
        created: new Date().toISOString().slice(0, 10)
    });
    res.redirect('/post/' + pid);
});

app.get('/post/:id/edit', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const p = DB.posts.find(x => x.id === parseInt(req.params.id, 10));
    if (!p) return res.status(404).end('no post');
    if (p.author_id !== me.id && me.role !== 'admin') return res.status(403).end('forbidden');
    res.send(layout('Ред. поста', `
        <h2>Редактирование</h2>
        <form method="post" action="/post/${p.id}/edit">
            <input name="title" value="${esc(p.title)}">
            <textarea name="body" rows="10">${esc(p.body)}</textarea>
            <input name="tags" value="${esc(p.tags)}">
            <button>Сохранить</button>
        </form>
    `, me));
});

app.post('/post/:id/edit', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const p = DB.posts.find(x => x.id === parseInt(req.params.id, 10));
    if (!p) return res.status(404).end('no post');
    if (p.author_id !== me.id && me.role !== 'admin') return res.status(403).end('forbidden');
    for (const k of Object.keys(req.body)) p[k] = req.body[k];
    res.redirect('/post/' + p.id);
});

app.get('/post/:id/delete', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const idx = DB.posts.findIndex(x => x.id === parseInt(req.params.id, 10));
    if (idx < 0) return res.status(404).end('no post');
    const p = DB.posts[idx];
    if (p.author_id !== me.id && me.role !== 'admin') return res.status(403).end('forbidden');
    DB.posts.splice(idx, 1);
    res.redirect('/');
});

app.get('/search', (req, res) => {
    const q = req.query.q || '';
    const me = currentUser(req);

    const echo = `<p>Результаты для: <b>${q}</b></p>`;

    let results = [];
    if (q) {
        const sql = `SELECT * FROM posts WHERE title LIKE '%${q}%' OR body LIKE '%${q}%'`;
        try {
            results = query(sql);
        } catch (e) {
            return res.status(500).send(layout('Ошибка',
                `<div class="error"><pre>SQL: ${sql}\n${e.stack}</pre></div>`, me));
        }
    }
    const html = results.map(p => `<div class="card">
        <a href="/post/${p.id}">${p.title}</a>
        <p>${p.body}</p>
    </div>`).join('');

    res.send(layout('Поиск', `
        <h2>Поиск</h2>
        <form method="get" action="/search">
            <input name="q" value="${q}" placeholder="Что искать?">
            <button>Искать</button>
        </form>
        ${echo}
        ${html || (q ? '<p>Ничего не найдено.</p>' : '')}
    `, me));
});

app.get('/fetch', (req, res) => {
    const target = req.query.url;
    if (!target) {
        return res.send(layout('SSRF Demo', `
            <h2>Загрузка URL</h2>
            <form method="get" action="/fetch">
                <input name="url" value="http://localhost:${CONFIG.PORT}/debug">
                <button>Fetch</button>
            </form>
            <p class="small">Попробуйте: http://localhost:3000/debug, file:///etc/passwd, http://169.254.169.254/...</p>
        `, currentUser(req)));
    }
    try {
        const u = url.parse(target);
        if (u.protocol === 'file:') {
            const data = fs.readFileSync(u.pathname, 'utf8');
            return res.send(layout('SSRF', `<pre>${esc(data)}</pre>`, currentUser(req)));
        }
        const mod = u.protocol === 'https:' ? https : http;
        const r = mod.get(target, (resp) => {
            let data = '';
            resp.on('data', c => data += c);
            resp.on('end', () => {
                res.send(layout('SSRF', `<h2>Ответ от ${esc(target)}</h2><pre>${esc(data.slice(0, 100000))}</pre>`, currentUser(req)));
            });
        });
        r.on('error', e => res.status(500).send(layout('SSRF', `<div class="error"><pre>${e.stack}</pre></div>`, currentUser(req))));
    } catch (e) {
        res.status(500).send(layout('SSRF', `<div class="error"><pre>${e.stack}</pre></div>`, currentUser(req)));
    }
});

app.get('/ping', (req, res) => {
    const host = req.query.host;
    if (!host) {
        return res.send(layout('Ping', `
            <h2>Ping</h2>
            <form method="get" action="/ping">
                <input name="host" value="127.0.0.1">
                <button>Пинг</button>
            </form>
            <p class="small">Попробуйте: 127.0.0.1; id    или   127.0.0.1 && cat /etc/passwd</p>
        `, currentUser(req)));
    }
    exec('ping -c 1 ' + host, { timeout: 5000 }, (err, stdout, stderr) => {
        res.send(layout('Ping', `
            <h2>Результат</h2>
            <p>Команда: <code>ping -c 1 ${esc(host)}</code></p>
            <pre>${esc(stdout || '')}${esc(stderr || '')}</pre>
            ${err ? `<div class="error">${esc(err.message)}</div>` : ''}
        `, currentUser(req)));
    });
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd;
    if (!cmd) return res.send(layout('Exec', `
        <h2>Exec (только для админов... но кто проверяет?)</h2>
        <form method="get" action="/exec">
            <input name="cmd" value="id">
            <button>Выполнить</button>
        </form>
    `, currentUser(req)));
    try {
        const out = execSync(cmd, { timeout: 5000 }).toString();
        res.send(layout('Exec', `<pre>${esc(out)}</pre>`, currentUser(req)));
    } catch (e) {
        res.status(500).send(layout('Exec', `<div class="error"><pre>${esc(e.stack || e.message)}</pre></div>`, currentUser(req)));
    }
});

app.all('/calc', (req, res) => {
    const expr = req.method === 'POST' ? req.body.expr : req.query.expr;
    let out = '';
    if (expr != null) {
        try {
            out = String(eval(expr));
        } catch (e) {
            out = 'Ошибка: ' + e.message;
        }
    }
    res.send(layout('Калькулятор', `
        <h2>Калькулятор</h2>
        <form method="post" action="/calc">
            <input name="expr" value="${esc(expr || '2+2')}">
            <button>Вычислить</button>
        </form>
        ${out ? `<pre>${esc(out)}</pre>` : ''}
        <p class="small">Попробуйте: <code>process.mainModule.require('child_process').execSync('id').toString()</code></p>
    `, currentUser(req)));
});

app.get('/greet', (req, res) => {
    const name = req.query.name || 'гость';
    let rendered;
    try {
        const tpl = 'return `Привет, ' + name + '!`;';
        rendered = new Function(tpl)();
    } catch (e) {
        rendered = 'Ошибка шаблона: ' + e.message;
    }
    res.send(layout('Привет', `
        <h2>SSTI Demo</h2>
        <form method="get" action="/greet">
            <input name="name" value="${esc(name)}">
            <button>Поздороваться</button>
        </form>
        <p>${rendered}</p>
        <p class="small">Попробуйте: <code>${'${process.env}'}</code> или <code>${'${7*7}'}</code> — но у нас `${}`, так что: <code>${'${'}process.version${'}'}</code></p>
    `, currentUser(req)));
});

app.get('/download', (req, res) => {
    const f = req.query.file;
    if (!f) return res.send(layout('Download', `
        <h2>Скачать файл</h2>
        <form method="get" action="/download">
            <input name="file" value="readme.txt">
            <button>Скачать</button>
        </form>
        <p class="small">Попробуйте: ../../etc/passwd</p>
    `, currentUser(req)));
    const full = path.join(__dirname, 'files', f);
    try {
        const data = fs.readFileSync(full);
        res.setHeader('Content-Disposition', `attachment; filename="${path.basename(f)}"`);
        res.send(data);
    } catch (e) {
        res.status(500).send(layout('Ошибка', `<div class="error"><pre>${esc(e.stack)}</pre></div>`, currentUser(req)));
    }
});

app.get('/backup', (req, res) => {
    const data = JSON.stringify(DB, null, 2);
    res.setHeader('Content-Disposition', 'attachment; filename="backup.json"');
    res.send(data);
});

app.get('/upload', (req, res) => {
    res.send(layout('Загрузка', `
        <h2>Загрузка файла</h2>
        <form method="post" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file">
            <button>Загрузить</button>
        </form>
        <p class="small">Нет проверки типа/размера. Файлы сохраняются в /uploads.</p>
    `, currentUser(req)));
});

app.post('/upload', (req, res) => {
    const ct = req.headers['content-type'] || '';
    if (!ct.startsWith('multipart/form-data')) {
        return res.status(400).send('need multipart');
    }
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks);
        const boundary = '--' + ct.split('boundary=')[1];
        const parts = body.toString('binary').split(boundary);
        for (const part of parts) {
            const m = /filename="([^"]*)"/.exec(part);
            if (!m) continue;
            const fname = m[1];
            const idx = part.indexOf('\r\n\r\n');
            if (idx < 0) continue;
            let data = part.slice(idx + 4).replace(/\r\n$/, '');
            const dest = path.join(CONFIG.UPLOAD_DIR, fname);
            try {
                fs.mkdirSync(CONFIG.UPLOAD_DIR, { recursive: true });
                fs.writeFileSync(dest, data, 'binary');
                log(`Uploaded: ${dest}`);
                return res.send(layout('OK', `<div class="ok">Загружено: <a href="/uploads/${encodeURIComponent(fname)}">/uploads/${esc(fname)}</a></div>`, currentUser(req)));
            } catch (e) {
                return res.status(500).send(layout('Ошибка', `<pre>${esc(e.stack)}</pre>`, currentUser(req)));
            }
        }
        res.status(400).send('no file field');
    });
});

app.post('/api/import/xml', (req, res) => {
    const xml = req.body && req.body.xml ? req.body.xml : (typeof req.body === 'string' ? req.body : '');
    try {
        let out = String(xml);
        const entRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"/g;
        let m;
        const entities = {};
        while ((m = entRe.exec(xml)) !== null) {
            const [, name, sys] = m;
            let value = '';
            try {
                if (sys.startsWith('file://')) {
                    value = fs.readFileSync(sys.replace('file://', ''), 'utf8');
                } else {
                    value = '(external fetch not implemented in demo)';
                }
            } catch (e) {
                value = 'ERROR: ' + e.message;
            }
            entities[name] = value;
        }
        out = out.replace(/&(\w+);/g, (_, n) => entities[n] !== undefined ? entities[n] : `&${n};`);
        res.json({ ok: true, parsed: out });
    } catch (e) {
        res.status(500).json({ error: e.message, stack: e.stack });
    }
});

app.post('/api/import/json', (req, res) => {
    const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    try {
        const obj = vm.runInNewContext('(' + raw + ')', {});
        function deepMerge(target, src) {
            for (const k of Object.keys(src || {})) {
                if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
                    target[k] = deepMerge(target[k] || {}, src[k]);
                } else if (typeof src[k] === 'object' && src[k] !== null) {
                    target[k] = deepMerge(target[k] || {}, src[k]);
                } else {
                    target[k] = src[k];
                }
            }
            return target;
        }
        deepMerge({}, obj);
        res.json({ ok: true, imported: obj });
    } catch (e) {
        res.status(400).json({ ok: false, error: e.message, stack: e.stack });
    }
});

app.get('/debug/proto', (req, res) => {
    res.json({ polluted: ({}).polluted });
});

app.get('/notes', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const mine = DB.notes.filter(n => n.user_id === me.id);
    res.send(layout('Заметки', `
        <h2>Мои заметки</h2>
        ${mine.map(n => `<div class="card"><a href="/notes/${n.id}">${esc(n.title)}</a></div>`).join('')}
        <form method="post" action="/notes">
            <input name="title" placeholder="Заголовок">
            <textarea name="content" placeholder="Содержимое"></textarea>
            <button>Создать</button>
        </form>
    `, me));
});

app.post('/notes', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    insertRow('notes', {
        user_id: me.id,
        title: req.body.title || '',
        content: req.body.content || ''
    });
    res.redirect('/notes');
});

app.get('/notes/:id', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const n = DB.notes.find(x => x.id === parseInt(req.params.id, 10));
    if (!n) return res.status(404).end('no note');
    res.send(layout('Заметка', `
        <h2>${esc(n.title)}</h2>
        <pre>${esc(n.content)}</pre>
        <p class="small">Владелец: ${n.user_id}</p>
    `, me));
});

app.get('/messages', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const list = DB.messages.filter(m => m.to_id === me.id || m.from_id === me.id);
    res.send(layout('Сообщения', `
        <h2>Сообщения</h2>
        ${list.map(m => `<div class="card">
            <a href="/messages/${m.id}">${esc(m.subject)}</a>
            <span class="small">от ${m.from_id} к ${m.to_id}</span>
        </div>`).join('') || '<p>Пусто</p>'}
        <form method="post" action="/messages">
            <input name="to_id" placeholder="Кому (id)">
            <input name="subject" placeholder="Тема">
            <textarea name="body" placeholder="Текст"></textarea>
            <button>Отправить</button>
        </form>
    `, me));
});

app.post('/messages', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    insertRow('messages', {
        from_id: me.id,
        to_id: parseInt(req.body.to_id, 10) || 0,
        subject: req.body.subject || '',
        body: req.body.body || '',
        read: false
    });
    res.redirect('/messages');
});

app.get('/messages/:id', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const m = DB.messages.find(x => x.id === parseInt(req.params.id, 10));
    if (!m) return res.status(404).end('no msg');
    res.send(layout('Сообщение', `
        <h2>${esc(m.subject)}</h2>
        <p class="small">От ${m.from_id} → ${m.to_id}</p>
        <pre>${esc(m.body)}</pre>
    `, me));
});

app.get('/api/users', (req, res) => {
    const filter = req.query.filter || '1=1';
    const sql = `SELECT * FROM users WHERE ${filter}`;
    try {
        const rows = query(sql);
        res.json({ ok: true, sql, users: rows });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message, sql, stack: e.stack });
    }
});

app.get('/api/posts', (req, res) => {
    const q = req.query.q || '';
    const sql = `SELECT * FROM posts WHERE title LIKE '%${q}%'`;
    try {
        res.json({ ok: true, sql, posts: query(sql) });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message, sql, stack: e.stack });
    }
});

app.post('/api/transfer', (req, res) => {
    const from = parseInt(req.body.from, 10);
    const to = parseInt(req.body.to, 10);
    const amount = parseInt(req.body.amount, 10);
    const fu = DB.users.find(u => u.id === from);
    const tu = DB.users.find(u => u.id === to);
    if (!fu || !tu) return res.status(404).json({ error: 'no user' });
    if (fu.balance < amount) return res.status(400).json({ error: 'insufficient' });
    setTimeout(() => {
        fu.balance -= amount;
        tu.balance += amount;
        res.json({ ok: true, from: fu.balance, to: tu.balance });
    }, 100);
});


app.post('/api/profile', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.status(401).json({ error: 'auth' });
    for (const k of Object.keys(req.body || {})) {
        me[k] = req.body[k]; 
    }
    res.json({ ok: true, user: me });
});

app.get('/api/ldap', (req, res) => {
    const uid = req.query.uid || '';
    const filter = `(&(uid=${uid})(objectClass=person))`;
    try {
        const m = /\(uid=([^)]*)\)/.exec(filter);
        const val = m ? m[1] : '';
        if (val.includes('*') || val.includes('|')) {
            return res.json({ ok: true, filter, results: DB.users.map(u => ({ uid: u.username, mail: u.email })) });
        }
        const u = DB.users.find(x => x.username === val);
        res.json({ ok: true, filter, results: u ? [{ uid: u.username, mail: u.email }] : [] });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/xpath', (req, res) => {
    const q = req.query.q || '';
    const xpath = `/users/user[username/text()='${q}']`;
    if (/' or '/i.test(q) || /'\s*or\s*'1'='1/i.test(q)) {
        return res.json({ ok: true, xpath, users: DB.users.map(u => u.username) });
    }
    const u = DB.users.find(x => x.username === q);
    res.json({ ok: true, xpath, users: u ? [u.username] : [] });
});

app.get('/api/validate', (req, res) => {
    const s = req.query.s || '';
    const re = /^(a+)+$/;
    const t0 = Date.now();
    const ok = re.test(s);
    res.json({ ok, ms: Date.now() - t0 });
});

app.get('/api/param', (req, res) => {
    res.json({ query: req.query, raw: req.url });
});

app.post('/api/yaml', (req, res) => {
    const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    try {
        const lines = raw.split('\n');
        const obj = {};
        for (const line of lines) {
            const m = /^(\w+):\s*(.*)$/.exec(line);
            if (m) {
                let v = m[2];
                if (v.startsWith('!!js/function')) {
                    v = new Function('return ' + v.slice(13))();
                } else if (/^\d+$/.test(v)) v = parseInt(v, 10);
                obj[m[1]] = v;
            }
        }
        res.json({ ok: true, parsed: obj });
    } catch (e) {
        res.status(500).json({ error: e.message, stack: e.stack });
    }
});


app.get('/go', (req, res) => {
    const to = req.query.to || '/';
    res.redirect(to);
});

app.get('/render', (req, res) => {
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Render</title></head>
<body>
<h1>Render</h1>
<p>Введите HTML в hash: <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
<div id="out"></div>
<script>
  document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>
</body></html>`);
});

app.get('/reset', (req, res) => {
    res.send(layout('Сброс', `
        <h2>Сброс пароля</h2>
        <form method="post" action="/reset">
            <input name="username" placeholder="Логин">
            <button>Получить токен</button>
        </form>
    `, currentUser(req)));
});

app.post('/reset', (req, res) => {
    const u = DB.users.find(x => x.username === req.body.username);
    if (!u) return res.send(layout('Сброс', '<div class="error">Нет такого</div>', currentUser(req)));

    const token = md5(u.username);
    res.send(layout('Сброс', `<div class="ok">Токен для ${esc(u.username)}: <code>${token}</code></div>
        <p class="small">Сбросьте: <a href="/reset/confirm?token=${token}&username=${encodeURIComponent(u.username)}">подтвердить</a></p>`, currentUser(req)));
});

app.get('/reset/confirm', (req, res) => {
    const { token, username } = req.query;
    const u = DB.users.find(x => x.username === username);
    if (!u) return res.status(404).end('no user');
    if (md5(u.username) !== token) return res.status(403).send('bad token');
    res.send(layout('Сброс', `
        <h2>Новый пароль для ${esc(u.username)}</h2>
        <form method="post" action="/reset/confirm">
            <input type="hidden" name="token" value="${esc(token)}">
            <input type="hidden" name="username" value="${esc(username)}">
            <input name="password" type="password" placeholder="Новый пароль">
            <button>Сбросить</button>
        </form>
    `, currentUser(req)));
});

app.post('/reset/confirm', (req, res) => {
    const { token, username, password } = req.body;
    const u = DB.users.find(x => x.username === username);
    if (!u) return res.status(404).end('no user');
    if (md5(u.username) !== token) return res.status(403).send('bad token');
    u.password = md5(password);
    res.send(layout('OK', '<div class="ok">Пароль изменён</div>', currentUser(req)));
});

app.get('/admin', (req, res) => {
    const me = currentUser(req);
    if (!me) return res.redirect('/login');
    const usersTable = DB.users.map(u => `<tr>
        <td>${u.id}</td><td>${u.username}</td><td>${u.password}</td>
        <td>${u.role}</td><td>${u.email}</td><td>${u.balance}</td>
    </tr>`).join('');

    res.send(layout('Админка', `
        <h2>Админ-панель</h2>
        ${me.role !== 'admin' ? '<div class="error">Вы не админ, но страница всё равно открыта 😈</div>' : ''}
        <table border="1" cellpadding="5">
            <tr><th>ID</th><th>Login</th><th>MD5 password</th><th>Role</th><th>Email</th><th>Balance</th></tr>
            ${usersTable}
        </table>
        <h3>Системная информация</h3>
        <pre>${esc(JSON.stringify({
            platform: process.platform,
            arch: process.arch,
            node: process.version,
            env: process.env,
            cwd: process.cwd(),
            mem: process.memoryUsage()
        }, null, 2))}</pre>
        <h3>Сбросить баланс</h3>
        <form method="post" action="/admin/setbalance">
            <input name="user_id" placeholder="ID">
            <input name="balance" placeholder="Баланс">
            <button>Установить</button>
        </form>
    `, me));
});

app.post('/admin/setbalance', (req, res) => {
    const u = DB.users.find(x => x.id === parseInt(req.body.user_id, 10));
    if (!u) return res.status(404).end('no user');
    u.balance = parseInt(req.body.balance, 10);
    res.redirect('/admin');
});


app.get('/debug', (req, res) => {
    res.send(layout('Debug', `
        <h2>Debug</h2>
        <h3>ENV</h3>
        <pre>${esc(JSON.stringify(process.env, null, 2))}</pre>
        <h3>CONFIG</h3>
        <pre>${esc(JSON.stringify(CONFIG, null, 2))}</pre>
        <h3>DB</h3>
        <pre>${esc(JSON.stringify(DB, null, 2).slice(0, 50000))}</pre>
        <h3>Audit log</h3>
        <pre>${esc(JSON.stringify(DB.audit_log.slice(-50), null, 2))}</pre>
    `, currentUser(req)));
});

app.get('/metrics', (req, res) => {
    res.json({
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        users: DB.users.length,
        posts: DB.posts.length,
        sessions: Object.keys(DB.sessions).length,
        cpu: os.cpus(),
        loadavg: os.loadavg(),
        hostname: os.hostname(),
        network: os.networkInterfaces()
    });
});


app.get('/logs', (req, res) => {
    try {
        const data = fs.readFileSync(CONFIG.LOG_FILE, 'utf8');
        res.send(layout('Логи', `<pre>${esc(data)}</pre>`, currentUser(req)));
    } catch (e) {
        res.send(layout('Логи', '<div class="error">Нет логов</div>', currentUser(req)));
    }
});


app.get('/readfile', (req, res) => {
    const f = req.query.f || '';
    try {
        const data = fs.readFileSync(f, 'utf8');
        res.send(layout('Файл', `<pre>${esc(data)}</pre>`, currentUser(req)));
    } catch (e) {
        res.status(500).send(layout('Ошибка', `<div class="error"><pre>${esc(e.stack)}</pre></div>`, currentUser(req)));
    }
});


app.get('/report', (req, res) => {
    const name = req.query.name || 'report';
    exec(`echo "Report for ${name}" > /tmp/report.txt && cat /tmp/report.txt`, (err, stdout, stderr) => {
        res.send(layout('Отчёт', `<pre>${esc(stdout || '')}${esc(stderr || '')}</pre>`, currentUser(req)));
    });
});


app.get('/convert', (req, res) => {
    const input = req.query.in || '';
    const child = spawn('bash', ['-c', `echo ${input} | base64`], { shell: true });
    let out = '';
    child.stdout.on('data', c => out += c);
    child.stderr.on('data', c => out += c);
    child.on('close', () => res.send(layout('Convert', `<pre>${esc(out)}</pre>`, currentUser(req))));
});


app.get('/welcome', (req, res) => {
    const name = req.query.name || 'друг';
    res.send(layout('Welcome', `<h2>Добро пожаловать, ${name}!</h2>`, currentUser(req)));
});


app.get('/admin/shell', (req, res) => {
    const c = req.query.c || 'whoami';
    try {
        const out = execSync(c).toString();
        res.send(layout('Shell', `<pre>${esc(out)}</pre>`, currentUser(req)));
    } catch (e) {
        res.status(500).send(layout('Shell', `<pre>${esc(e.stack)}</pre>`, currentUser(req)));
    }
});


app.get('/api/config', (req, res) => {
    res.json(CONFIG);
});

app.get('/api/env', (req, res) => {
    res.json(process.env);
});


app.get('/flags', (req, res) => {
    res.send(layout('Флаги', `
        <h2>Флаги (для проверки)</h2>
        <ul>
            <li>SQLi login: <code>FLAG{admin_secret_note_1}</code> — в /debug</li>
            <li>Path traversal: <code>FLAG{file_read_ok}</code></li>
            <li>RCE: <code>FLAG{rce_pwned}</code></li>
            <li>XXE: <code>FLAG{xxe_ok}</code></li>
            <li>IDOR notes: <code>FLAG{admin_note_1}</code></li>
            <li>JWT none: <code>FLAG{jwt_none}</code></li>
        </ul>
    `, currentUser(req)));
});


try {
    fs.mkdirSync(path.join(__dirname, 'files'), { recursive: true });
    fs.writeFileSync(path.join(__dirname, 'files', 'readme.txt'), 'This is readme. Try ../../etc/passwd\nFLAG{file_read_ok}\n');
} catch (e) {}


app.use((req, res) => {
    res.status(404).send(layout('404', `
        <h2>404</h2>
        <p>Не найдено: <code>${esc(req.url)}</code></p>
    `, currentUser(req)));
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send(layout('Ошибка', `
        <h2>500 Internal Server Error</h2>
        <pre>${esc(err.stack || err.message)}</pre>
    `, currentUser(req)));
});

setInterval(() => {
}, 60000);


app.listen(CONFIG.PORT, () => {
    log(`===========================================`);
    log(`  VulnBlog v${CONFIG.VERSION} запущен на порту ${CONFIG.PORT}`);
    log(`  ⚠️  Это намеренно уязвимое приложение!`);
    log(`  Не запускайте в публичной сети.`);
    log(`===========================================`);
    console.log(`\n  → http://localhost:${CONFIG.PORT}\n`);
});

module.exports = app;
