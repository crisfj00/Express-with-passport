const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const port = 3000
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const https = require('https');
const fs = require('fs');
const bcrypt = require("bcryptjs")
const tlsServerKey = fs.readFileSync('./webserver.key.pem');
const tlsServerCrt = fs.readFileSync('./webserver.crt.pem');
const app = express()
const fortune = require('fortune-teller')
const mysql = require("mysql")
const dotenv = require('dotenv')
const httpsOptions = {
    key: tlsServerKey,
    cert: tlsServerCrt
};
const server = https.createServer(httpsOptions, app);
dotenv.config({ path: './.env'})

server.listen(443);
server.on('listening', onListening);

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
})

db.connect((error) => {
    if(error) {
        console.log(error)
    } else {
        console.log("MySQL connected!")
    }
})


function checkToken (req, res, next) {
//get authcookie from request

const authcookie = req.cookies.authcookie;

try{

	const user = jwt.verify(authcookie,jwtSecret); 
	req.user=user;
	next();
	
}catch(err){
		res.clearCookie("authcookie");
		return res.redirect("/login");
	}

 }

function onListening() {
    const addr = server.address();
    const bind = typeof addr === 'string'
        ? 'pipe ' + addr
        : 'port ' + port;
    console.log('Listening on ' + bind);
}
app.use(cookieParser())
app.use(logger('dev'))

/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  function (username, password, done) {
  
      db.query('SELECT name, password FROM users WHERE name = ?', [username, password], async (error, res, fields) => {
        if(error){
            console.log(error)
        }
        
          if( res.length > 0 ) {
	
		    Object.keys(res).forEach(function(key) {
		      var row = res[key];   
		      const cmp = bcrypt.compare(password, row.password); 	
		      	
		    if (cmp) {
		      const user = { 
			username: username,
			description: 'the user that deserves to contact the fortune teller'
		      }
		      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
		    }
		    else
		    return done(null, false) 
		    // in passport returning false as the user object means that the authentication process failed. 
	 });
		
        } else {
            return done(null, false)  
        }
        
    })

  }
))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.


app.get('/', checkToken, (req, res) => {
  res.render('index.pug', { fortune: fortune.fortune() });
})

 

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.get('/register',
  (req, res) => {
    res.render('register.pug', { message: '' })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.get('/logout',(req,res) => {
res.clearCookie("authcookie");
return res.redirect('/');
});

app.post("/register", (req, res) => {    
    const { username, password, password_conf } = req.body
    
    db.query('SELECT name FROM users WHERE name = ?', [username], async (error, result) => {
        if(error){
            console.log(error)
        }
        
          if( result.length > 0 ) {
            return res.render('register.pug', {
                message: 'This username is already in use'
            })
        } else if(password !== password_conf) {
            return res.render('register.pug', {
                message: 'Passwords do not match!'
            })
        }
        
        let hashedPassword = await bcrypt.hash(password, 8)

        db.query('INSERT INTO users SET?', {name: username, password: hashedPassword}, (error, result) => {
            if(error) {
                console.log(error)
            } else {
                return res.redirect('/login');
            }
        })
    })

})

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)

    
    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    
    res.cookie('authcookie',token,{
    	httpOnly: true,
    	secure: true}) 
    return res.redirect('/');
  }
)


app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at https://10.0.2.10`)
})


