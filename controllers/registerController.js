const User = require("../model/users")
const bcrypt = require('bcrypt')

const handleNewUser = async (req, res) => {
    const { user, pwd} = req.body; // bodyt has an object with user and password
    if(!user || !pwd) return res.status(400).json(
        {"message": "username and password required"});
    //check for duplicates in the database
    const duplicate = await User.findOne({username: user}).exec();
    if(duplicate) return res.sendStatus(409)

    try{
        // encrpt the password
        const hashedPwd = await bcrypt.hash(pwd, 10); // wait for response
        // store the new user
        const result = await User.create({
            "username": user,
            "password": hashedPwd
        }); 
        console.log(result)
        res.status(201).json({"success": `New user ${user} created`})
    } catch(err){
        res.status(500).json({"message": err.message});
    }
}

module.exports = {handleNewUser};