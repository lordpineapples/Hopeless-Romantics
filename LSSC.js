const express = require("express") // imports express framework
const crypt = require("crypto") // imports crypto module for hashing
const app = express() // creates an express application
const session = require("express-session") // imports session middleware
const cookieParser = require("cookie-parser") // imports cookie parser middleware
const mysql = require("mysql2") // imports mysql2 for database connection
const pass = process.env.ROOTPASS // retrieves database password from environment variable
const conn = mysql.createConnection({ // creates a connection to the MySQL database
    host: "localhost",
    user: "root",
    password: pass,
    database: "paws",
    port: 3306
})

app.use(express.urlencoded({ extended: true })) // parses URL-encoded bodies
app.use(express.static("public")) // serves static files from public directory
app.use(cookieParser()) // uses cookie parser middleware

app.use(session({ // configures session middleware
    secret: process.env.SESSION_SECRET, // secret for signing session ID cookie
    resave: false, // prevents resaving unchanged sessions
    saveUninitialized: false, // prevents storing empty sessions
    cookie: {
        maxAge: 60000 * 60, // cookie expiry in milliseconds (1 hour)
        httpOnly: true, // protects against XSS attacks
        secure: false // sets to true if using HTTPS
    }
}))

const hashRounds = 100 // number of rounds for hashing
const hashLength = 64 // length of the hash
const salt = "salt" // salt for hashing

conn.connect(function(err) { // connects to the database
    if (err) {
        console.log("Could not connect to MySQL", err) // logs error if connection fails
    } else {
        console.log("Database connection established") // logs success message
    }
})

app.post("/signup", function(req, res) { // handles signup requests
    const { password: plainPass, userName: username, fname, lname, gpa } = req.body // destructures request body
    const hashedPass = crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString(`hex`) // hashes the password
    const sql = "INSERT INTO student (fname, lname, gpa, user_id, password, salt) VALUES (?, ?, ?, ?, ?, ?)" // SQL query for inserting a new student
    conn.query(sql, [fname, lname, gpa, username, hashedPass, salt], function(err, result) { // executes the query
        if (err) {
            console.log("There was an error inserting a student", err) // logs error if insertion fails
        } else {
            res.send(`<p>You have inserted ${fname} ${lname} into ${result.affectedRows} row(s). <a href="login.html">Login</a> here.</p>`) // sends success message
        }
    })
})

app.get("/profile", function(req, res) { // handles profile requests
    if (!req.session.user) { // checks if user is logged in
        return res.send(`
            <h1>Access Denied</h1>
            <p>You are not logged in.</p>
            <a href="login.html">Login Here</a>
        `) // sends access denied message
    }

    res.send(`
        <h1>User Profile</h1>
        <p>Welcome, ${req.session.user.user_id}!</p>
        <p>Your GPA is ${req.session.user.gpa}.</p>
        <a href="/logout">Logout</a>
    `) // sends user profile information
})

app.get("/logout", function(req, res) { // handles logout requests
    req.session.destroy(function(err) { // destroys the session
        if (err) {
            return res.send("Error logging out.") // sends error message if logout fails
        }

        res.clearCookie("connect.sid") // clears session cookie

        res.send(`
            <h1>Logged Out</h1>
            <p>You have successfully logged out!</p>
            <a href="login.html">Login Again</a>
        `) // sends logout success message
    })
})

app.post("/login", function(req, res) { // handles login requests
    const { password: plainPass, username } = req.body // destructures request body
    const hashedPass = crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString(`hex`) // hashes the password
    const sql = 'SELECT * FROM student WHERE user_id = ? AND password = ?' // SQL query for user authentication
    conn.query(sql, [username, hashedPass], function(err, result) { // executes the query
        if (err) {
            res.send(err) // sends error message if query fails
        } else {
            if (result.length === 0) { // checks if user exists
                console.log('results of the query', result) // logs query results
                res.send('<p>Your password or username are incorrect.<br> <a href="login.html">Login</a> here.</p>') // sends error message
            } else {
                req.session.user = { // stores user information in session
                    user_id: username,
                    gpa: result[0].gpa
                }

                req.session.save(function(err) { // saves session
                    if (err) {
                        return res.send("Error saving session.") // sends error message if saving fails
                    }

                    res.send(`
                        <h1>Login Successful!</h1>
                        <p>Welcome, ${username}!</p>
                        <p><a href="/profile">View Your Profile</a></p>
                    `) // sends success message
                })
            }
        }
    })
})

app.listen(3000) // starts the server on port 3000
