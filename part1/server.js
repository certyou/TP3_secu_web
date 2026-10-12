const express = require('express');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const PORT = 4000;
app.use(express.json());
app.use(cookieParser());
const SECRET_KEY = "secret";
const USERS = {
    "alice": "password1",
    "bob": "password2"
};

const authMiddleware = function (req, res, next) {
  // 1. recuperer le jeton (en-tete Authorization ou cookie)
    const token = req.cookies.accessToken;
    if (!token) {
        return res.status(401).json({ message: "Accès refusé : Aucun jeton fourni." });
    }
    try {
        // 2. verifier sa signature et sa date d'expiration
        const decoded = jwt.verify(token, SECRET_KEY);
        const xsrfTokenHeader = req.headers.authorization;
        console.log(xsrfTokenHeader)
        decoded_xsrfToken = `Bearer ${decoded.xsrfToken}`
        if (!xsrfTokenHeader || xsrfTokenHeader !== decoded_xsrfToken) {
            return res.status(401).json({ message: `Accès refusé : Jeton CSRF invalide ou manquant (${xsrfTokenHeader} =/= ${decoded_xsrfToken}).` });
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: "Jeton invalide ou expiré." });
    }
};

app.post('/users/signin', function (req, res) {
    const { username, password } = req.body;
    if (USERS[username] && USERS[username] === password) {
        const xsrfToken = crypto.randomBytes(32).toString('hex');
        const expiredAt = moment().add(1, 'hours').valueOf();
        const payload = {
            username: username,
            xsrfToken: xsrfToken,
            exp: Math.floor(expiredAt/1000)
        };
        const token = jwt.sign(payload, SECRET_KEY);
        res.cookie('accessToken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'strict'
        });
        return res.json({
            user: { username: username },
            xsrfToken: xsrfToken,
            expiredAt: expiredAt
        });
    } else {
        return res.status(401).json({ message: "Identifiants incorrects" });
    }
});

app.get('/users/getList', authMiddleware, (req, res) => {
    const userList = Object.keys(USERS).map(name => ({ username: name }));
    res.json({ userlist: userList });
});

app.get('/verifyToken', authMiddleware, (req, res) => {
    res.json({
        message: "Le jeton est valide.",
        user: req.user.username
    });
});

app.get('/users/logout', (req, res) => {
    res.clearCookie('accessToken');
    res.json({ message: "Déconnexion réussie. Cookie supprimé." });
});

app.listen(PORT, () => {
    console.log(`Le serveur JWT est démarré sur http://localhost:${PORT}`);
});
