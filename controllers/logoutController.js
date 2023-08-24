User = require("../model/users")

const handleLogout = async (req, res) =>{
    // On client, also delete the accessToken
    const cookies = req.cookies // look for a cookies
    if(!cookies?.jwt) return res.sendStatus(204) // No content to sed back
    const refreshToken = cookies.jwt; // the refresh token

    // is refreshToke in db
    const foundUser = await User.findOne({refreshToken}).exec()
    if(!foundUser){
        res.clearCookie('jwt', {httpOnly: true, sameSite: 'None'});
        return res.sendStatus(204);
    }

    // delete the refreshToken in the database
    foundUser.refreshToken = ''
    const result = await foundUser.save()
    console.log(result)

    res.clearCookie('jwt', {httpOnly: true, sameSite: 'None'}) // secure: true - only serves on https
    res.sendStatus(204);
}

module.exports = {handleLogout}