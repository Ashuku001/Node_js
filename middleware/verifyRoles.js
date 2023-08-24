const verifyRoles = (...allowedRoles) => {
    return (req, res, next) => { 
        console.log("Verifiy;....................")
        if(!req?.roles) return res.sendStatus(401); // if there is req but no roles or there is no req
        const rolesArray = [...allowedRoles]
        console.log(rolesArray);
        console.log(req.roles);
        const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);
        if(!result) return res.sendStatus(401);
        next()
    } 
}

module.exports = verifyRoles