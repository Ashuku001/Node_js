require('dotenv').config();
const express = require("express")
const app = express()
const path = require('path')
const cors = require('cors')
const corsOptions = require('./config/corsOptions')
const {logger} = require('./middleware/logEvents')
const errorHandler = require('./middleware/errorHandler')
const verifyJWT = require('./middleware/verifyJWT');
const cookieParser = require('cookie-parser')
const credentials = require("./middleware/credentials")
const mongoose = require("mongoose")
const connectDB = require('./config/dbConn')

const PORT = process.env.PORT || 3500;

//connect to DB
connectDB()

//custom middleware logger
app.use(logger);

// Handle options credentials check-before CORS!
// and fetch cookies credentials requirement
// app.use(credentials)

// cross origin resorce sharing
app.use(cors(corsOptions));

// build-in middleware to handle urlencoded form data
app.use(express.urlencoded({extended: false}))

// built-in middleware for json
app.use(express.json())

//middlewre for cookies
app.use(cookieParser());

// Serce static files using a middleware root and subdir
app.use('/', express.static(path.join(__dirname, "/public")))
// router to the root and a sub directory
app.use('/', require('./routes/root'));
app.use('/register', require('./routes/register'));
app.use('/auth', require('./routes/auth')); // will assign a logged in user a token
app.use('/logout', require('./routes/logout')); // will assign a logged in user a token

app.use("/refresh", require("./routes/refresh"))

// before accessing anything after here verify the access token
app.use(verifyJWT);
app.use('/employees', require('./routes/api/employees'));

// app.all to all http methods at once does no accept regex
// app.use for middleware
app.all('*', (req, res) => {
    // res.sendFile('./views/index.html', {root: __dirname});
    res.status(404);
    if(req.accepts('html')){
        res.sendFile(path.join(__dirname, 'views', '404.html', )) // sends 302 by default
    }else if(req.accepts('json')){
        res.json({error: "404 Not Found"})
    } else {
        res.type('txt').send("404 Not Found")
    }
})

app.use(errorHandler)

mongoose.connection.once("open", () => {
    console.log("Connected to mongoDB")
    app.listen(PORT, ()=>console.log('Server running at port:', PORT))
})
