const jwt = require('jsonwebtoken');

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization; // authenticate the request if is allowed
    if(!authHeader?.startsWith("Bearer ")) return res.sendStatus(401); // no authotication token was provided
    const token = authHeader.split(' ')[1] // get the token split it from the bearer
    jwt.verify(
        token, // received token
        process.env.ACCESS_TOKEN_SECRET, // allowed access token
        (err, decoded) => {
            if(err) return res.sendStatus(403); // invalid token
            req.user = decoded.UserInfo.username; // else the decoded username valid token
            req.roles = decoded.UserInfo.roles;
            next() // for middleware
        }
    )
}

module.exports = verifyJWT;