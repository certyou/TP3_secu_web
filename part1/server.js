const express = require('express');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const port = 4000;
app.use(express.json());
app.use(cookieParser());
const secret_key = "secret";
const users = {
    "alice": "password1",
    "bob": "password2"
};

const authMiddleware = function (req, res, next) {
  // 1. recuperer le jeton (en-tete Authorization ou cookie)
    const token = req.cookies.accessToken;
    if (!token) {
        return res.status(401).json({ message: "no token" });
    }
    try {
        // 2. verifier sa signature et sa date d'expiration
        const decoded = jwt.verify(token, secret_key);
        const xsrfTokenHeader = req.headers['token'];
        if (!xsrfTokenHeader || xsrfTokenHeader !== decoded.token) {
            return res.status(401).json({ message: "token invalid" });
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: "token error" });
    }
};

app.post('/users/signin', function (req, res) {
    // check user creds
    const { username, password } = req.body;
    if (users[username] && users[username] === password) {
        // generate csrf token
        const token_csrf = crypto.randomBytes(32).toString('hex');
        // add expiration (1h)
        const expiredAt = moment().add(1, 'hours').valueOf();
        const payload = {
            username: username,
            token: token_csrf,
            exp: Math.floor(expiredAt/1000)
        };
        const token = jwt.sign(payload, secret_key);
        res.cookie('accessToken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'strict'
        });
        return res.json({
            user: { username: username },
            token: token_csrf,
            expiredAt: expiredAt
        });
    } else {
        return res.status(401).json({ message: "id incorrect" });
    }
});

app.get('/users/getList', authMiddleware, (req, res) => {
    const userList = Object.keys(users).map(name => ({ username: name }));
    res.json({ userlist: userList });
});

app.get('/verifyToken', authMiddleware, (req, res) => {
    res.json({
        message: "valid token",
        user: req.user.username
    });
});

app.get('/users/logout', (req, res) => {
    res.clearCookie('accessToken');
    res.json({ message: "you are disconnected" });
});

app.listen(port, () => {
    console.log(`server started: http://localhost:${port}`);
});
