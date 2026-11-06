const express = require("express") // imports express framework
const app = express() // creates an instance of express
const session = require("express-session") // imports session middleware
const cookieParser = require("cookie-parser") // imports cookie parser middleware
const PORT = 3000 // defines the port number

app.use(cookieParser()) // uses cookie parser middleware

app.use(session({ // configures session middleware
  secret: 'your-secure-secret-key', // secret key for signing session ID cookie
  resave: false, // prevents resaving unchanged sessions
  saveUninitialized: false, // prevents storing empty sessions
  cookie: { 
    maxAge: 60000 * 60, // cookie expiry set to 1 hour
    httpOnly: true, // protects against XSS attacks
    secure: false // sets to true if using HTTPS
  }
}))

const user = { // user object for demonstration
    name: "Dave",
    zip_code: 30311,
    address: "Atlanta" // corrected property name to lowercase
}

// login endpoint
app.get("/login", (req, res) => {
    req.session.user = user // stores user in session

    req.session.save(err => { // saves session
        if (err) {
            return res.send("Error saving session.") // handles session save error
        }

        res.send(`
            <h1>Login Successful!</h1>
            <p>Welcome, ${req.session.user.name}!</p>
            <a href="/profile">View Profile</a>
        `) // sends success response
    })
})

// profile endpoint
app.get("/profile", (req, res) => {
    if (!req.session.user) { // checks if user is logged in
        return res.send(`
            <h1>You are not logged in.</h1>
            <a href="/login">Login Here</a>
        `) // prompts to login if not logged in
    }

    res.send(`
        <h1>User Profile</h1>
        <p>Username: ${req.session.user.name}</p>
        <p>Zip Code: ${req.session.user.zip_code}</p>
        <p>Address: ${req.session.user.address}</p> <!-- corrected property name to lowercase -->
        <a href="/logout">Logout</a>
    `) // sends user profile information
})

// logout endpoint
app.get("/logout", (req, res) => {
    req.session.destroy(err => { // destroys session
        if (err) {
            return res.send("Error logging out.") // handles logout error
        }

        res.clearCookie("connect.sid") // clears session cookie

        res.send(`
            <h1>Logged Out</h1>
            <p>You have successfully logged out!</p>
            <a href="/login">Login Again</a>
        `) // sends logout confirmation
    })
})

app.listen(PORT, () => console.log(`Server running on port ${PORT}`)) // starts server
