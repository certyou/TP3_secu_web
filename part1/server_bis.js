const express = require('express');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const jwksClient = require('jwks-rsa'); // Ajout de la librairie jwks-rsa

const app = express();
const port = 4000;
app.use(express.json());
app.use(cookieParser());

// Base de données simulée
const users = {
    "alice": "password1",
    "bob": "password2"
};

// ==========================================
// Configuration Keycloak (jwks-rsa)
// ==========================================
// On indique l'URL où Keycloak expose ses clés publiques (jwks_uri)
const client = jwksClient({
  jwksUri: 'http://localhost:8180/realms/realmtest/protocol/openid-connect/certs' 
});

// Fonction pour récupérer la clé publique correspondant au "kid" du jeton
function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      console.error("Erreur lors de la récupération de la clé publique:", err);
      return callback(err, null);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// ==========================================
// Middleware d'authentification modifié pour Keycloak
// ==========================================
const authMiddleware = function (req, res, next) {
    // 1. On récupère le jeton depuis l'en-tête Authorization envoyé par le client (Postman)
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: "no token or invalid format" });
    }

    const token = authHeader.split(' ')[1]; // Extraction du jeton

    // 2. Vérification de la signature asymétrique de Keycloak
    jwt.verify(token, getKey, { 
        algorithms: ['RS256'], // Algorithme par défaut de Keycloak
        issuer: 'http://localhost:8180/realms/realmtest' // Vérification de l'émetteur (sécurité)
    }, (err, decoded) => {
        if (err) {
            console.error("Erreur de vérification:", err.message);
            return res.status(401).json({ message: `token error : ${err.message}` });
        }
        
        // 3. Jeton valide : on stocke les infos de l'utilisateur
        req.user = decoded;
        next();
    });
};


// ==========================================
// Routes de l'API
// ==========================================

// NB : Avec Keycloak, c'est Keycloak qui gère le /signin. 
// Cette route locale ne sert plus vraiment si Keycloak gère toute l'authentification.
// Je la laisse ici telle quelle, mais en production, elle serait supprimée.
app.post('/users/signin', function (req, res) {
    const { username, password } = req.body;
  if (users[username] && users[username] === password) {
    const xsrfToken = crypto.randomBytes(32).toString('hex');
    const header = { algorithm: 'HS256' };
    const payload = {
      username: username,
      xsrf_token: xsrfToken,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60),
    };
    
    // NB : Cette clé secrète locale n'a rien à voir avec Keycloak.
    const secret_key = "secret"; 
    const jwtoken = jwt.sign(payload, secret_key, header);
    
    res.cookie('accessToken', jwtoken, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict'
    });
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
  res.json({ 
      userlist: userList, 
      keycloak_user: req.user.preferred_username // On renvoie l'info Keycloak pour prouver que ça marche
  });
});

app.get('/verifyToken', authMiddleware, (req, res) => {
    res.json({
        message: "valid token from Keycloak",
        user: req.user.preferred_username // Dans Keycloak, le nom est souvent dans preferred_username
    });
});

app.get('/users/logout', (req, res) => {
    res.clearCookie('accessToken');
    res.json({ message: "you are disconnected locally" });
});

app.listen(port, () => {
    console.log(`server started: http://localhost:${port}`);
});