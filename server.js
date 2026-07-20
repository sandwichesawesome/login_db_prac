const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./app.db'); // 파일 기반 DB (DB 확인용)

// 미들웨어 설정
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'study-secret-key',
    resave: false,
    saveUninitialized: false
}));

// DB 테이블 생성 (서버 시작 시 1회)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        nickname TEXT
    )`);
});

// 로그인 상태 확인 미들웨어
const requireLogin = (req, res, next) => {
    if (req.session.userId) return next();
    res.redirect('/login');
};

// --- 라우터 ---

// 1. 메인 페이지
app.get('/', (req, res) => {
    res.render('index', { user: req.session.userId });
});

// 2. 회원가입
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    const { username, password, nickname } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)`,
            [username, hashedPassword, nickname],
            (err) => {
                if (err) return res.send('이미 존재하는 아이디거나 오류가 발생했습니다.');
                res.redirect('/login');
            });
    } catch (err) {
        res.status(500).send('서버 오류');
    }
});

// 3. 로그인
app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.send('아이디가 존재하지 않습니다.');

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.userId = user.id;
            req.session.nickname = user.nickname;
            res.redirect('/profile');
        } else {
            res.send('비밀번호가 일치하지 않습니다.');
        }
    });
});

// 4. 로그아웃
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 5. 사용자별 맞춤 페이지 (인가된 사용자만 접근 가능)
app.get('/profile', requireLogin, (req, res) => {
    res.render('profile', {
        userId: req.session.userId,
        nickname: req.session.nickname
    });
});

app.listen(3000, () => {
    console.log('서버 실행 중: http://localhost:3000');
});