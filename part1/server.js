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
  const cookie = req.cookies.accessToken;
  if (!cookie) {
    return res.status(401).json({ message: "no token" });
  }
  try {
    // 2. verifier sa signature et sa date d'expiration
    const decoded_cookie = jwt.verify(cookie, secret_key, { algorithm: 'HS256' })
    const xsrf_token_cookie = `Bearer ${decoded_cookie.xsrf_token}`
    const xsrf_token_header = req.headers.authorization;
    if (!xsrf_token_header || xsrf_token_header !== xsrf_token_cookie) {
      return res.status(401).json({ message: `token invalid` });
    }
    req.user = decoded_cookie;
    next();
  } catch (error) {
      return res.status(401).json({ message: `token error : ${error}` });
  }
};

app.post('/users/signin', function (req, res) {
    // check user creds
    const { username, password } = req.body;
  if (users[username] && users[username] === password) {
    // génération CSRF
    const xsrfToken = crypto.randomBytes(32).toString('hex');
    // header du JWT
    header = {
      algorithm: 'HS256'
    }
    // payload du JWT
    payload = {
      username: username,
      xsrf_token: xsrfToken,
      iat: Math.floor(Date.now() / 1000),               // date génération
      exp: Math.floor(Date.now() / 1000) + (60 * 60),   // date expiration
    }
    // JWT (avec sa signature)
    jwtoken = jwt.sign(payload, secret_key, header)
    // génération du cookie comprenant le JWT
    res.cookie('accessToken', jwtoken, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict'
    });
    // réponse au client
    return res.json({
      user: { username: username },
      xsrf_token: xsrfToken
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
