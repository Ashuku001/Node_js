User = require("../model/users")
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const handleLogin = async (req, res) => {
    const { user, pwd } = req.body; // bodyt has an object with user and password
    console.log(req.body)
    if (!user || !pwd) return res.status(400).json(
        { "message": "username and password required" });
    const foundUser = await User.findOne({username: user}).exec()
    console.log('founuser', foundUser)
    if (!foundUser) return res.sendStatus(401); // unauthorized
    console.log("........'gh98jhhhhh98gss")
    // evaluate the password
    const match = await bcrypt.compare(pwd, foundUser.password);
    console.log('Match ', match, "pwd", pwd, "hash", foundUser.password)
    if (match) {
        const roles = Object.values(foundUser.roles);
        // create JWTs(jason web tokens)
        const accessToken = jwt.sign(
            {
                "UserInfo": {
                    "username": foundUser.username,
                    "roles": roles
                }
            }, // add a username to the token
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '60s' }
        );
        const refreshToken = jwt.sign(
            { "username": foundUser.username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' }
        );
        // Saving refreshToken with current user
        foundUser.refreshToken = refreshToken;
        const result = await foundUser.save()
        console.log(result)
        res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', maxAge: 24 * 60 * 60 * 1000 });
        res.json({ accessToken });
    } else {
        res.sendStatus(401)
    }
}

module.exports = { handleLogin }