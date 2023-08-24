User = require("../model/users")
const jwt = require('jsonwebtoken');

const handleRefreshToken = async (req, res) =>{
    const cookies = req.cookies // look for a cookies
    if(!cookies?.jwt) return res.sendStatus(401) // or we have a cookie but no jwt
    console.log(cookies.jwt);
    const refreshToken = cookies.jwt;

    const foundUser = await User.findOne({ refreshToken }).exec()
    if(!foundUser) return res.sendStatus(403); // forbidden
    // evaluate the jwt
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if(err || foundUser.username !== decoded.username) return res.sendStatus(403)
            const roles = Object.values(foundUser.roles)
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                {expiresIn: '30s'}
            );
            res.json({accessToken})
        }
    )
}

module.exports = {handleRefreshToken}