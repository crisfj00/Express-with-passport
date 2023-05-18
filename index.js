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
const scryptPbkdf = require('scrypt-pbkdf')
const axios = require('axios')
const GitHubStrategy = require('passport-github2').Strategy;
const salt = scryptPbkdf.salt(32)  // returns an ArrayBuffer filled with 16 random bytes
const derivedKeyLength = 32  // in bytes
const OpenIDConnectStrategy = require('passport-openidconnect').Strategy;
const session = require('express-session');
const ScryptParams = { //strong
  N: 1048576,
  r: 8,
  p: 2
}

const normalScryptParams = {
  N: 131072,
  r: 8,
  p: 1
}

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

function hexStringToUint8Array(hexString){
  if (hexString.length % 2 !== 0){
    throw "Invalid hexString";
  }/*from  w w w.  j  av a 2s  . c  o  m*/
  var arrayBuffer = new Uint8Array(hexString.length / 2);

  for (var i = 0; i < hexString.length; i += 2) {
    var byteValue = parseInt(hexString.substr(i, 2), 16);
    if (isNaN(byteValue)){
      throw "Invalid hexString";
    }
    arrayBuffer[i/2] = byteValue;
  }

  return arrayBuffer;
}


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

app.use(session({
  secret: jwtSecret.toString('base64'),
  resave: false,
  saveUninitialized: false,
}));

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
  
      db.query('SELECT name, password, salt FROM users WHERE name = ?', [username, password], async (error, res, fields) => {
        if(error){
            console.log(error)
        }
        
          if( res.length > 0 ) {
			    Object.keys(res).forEach(function(key) {
		      var row = res[key];   
		      
		      var params;
		            		      
		      scryptPbkdf.scrypt(password, hexStringToUint8Array(row.salt), derivedKeyLength,ScryptParams).then(  // key is an ArrayBuffer
		  	function(key) { // key is an ArrayBuffer
				let hashedPassword = Buffer.from(key).toString('hex');
			      	console.log('Username submitted: '+ username);
      		      		console.log('Password submitted: '+ password);
      		      
				const cmp = (hashedPassword == row.password);
				
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

			},function(error) { console.log(error) })

	 });
		
        } else {
            return done(null, false)  
        }
        
    })

  }
))


app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(passport.authenticate('session'));

passport.use(new GitHubStrategy({
  clientID: process.env.OAUTH2_CLIENT_ID,
  clientSecret: process.env.OAUTH2_CLIENT_SECRET,
  callbackURL: "/oauth/github/callback"
	},
	function(accessToken, refreshToken, profile, done) {

	   return done(null, profile);
	}
));

passport.use(new OpenIDConnectStrategy({
	  issuer: 'accounts.google.com',
	  authorizationURL: process.env.GOOGLE_AUTHORIZE_URL,
	  tokenURL: process.env.GOOGLE_TOKEN_URL,
	  userInfoURL: process.env.GOOGLE_USER_URL,
	  clientID: process.env.GOOGLE_CLIENT_ID,
	  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	  // needs FULL URL in Authing console.
	  callbackURL: '/oauth/google/callback',
	  scope: [ 'profile' ],
	  state: true
	},
	function verify(issuer, profile, cb) {
	  // you can verify and insert user into your database
	  return cb(null, profile);
}));

app.get('/', checkToken, (req, res) => {
  res.render('index.pug', { fortune: fortune.fortune() });
})
 

app.get('/login',
  (req, res) => {
    res.sendFile('views/login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.get('/register',
  (req, res) => {
    res.render('register.pug', { message: '' })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.get('/oauth/google',passport.authenticate('openidconnect'));


app.get('/oauth/google/callback',passport.authenticate('openidconnect', { failureRedirect: '/login', session: false }),
function(req, res) {
    
      const jwtClaims = {
      sub: req.user.id,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user', // just to show a private JWT field
    }

    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('authcookie',token,{
    	httpOnly: true,
    	secure: true}) 
    return res.redirect('/');
  
});


app.get('/oauth/github',passport.authenticate('github',{ scope: [ 'user:email' ], session: false}));


app.get('/oauth/github/callback',passport.authenticate('github', { failureRedirect: '/login', session: false }),
function(req, res) {
    
      const jwtClaims = {
      sub: req.user.id,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user', // just to show a private JWT field
    }

    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('authcookie',token,{
    	httpOnly: true,
    	secure: true}) 
    	
    res.clearCookie("connect.sid");
    return res.redirect('/');
  
});

app.get('/logout',(req,res) => {
	res.clearCookie("authcookie");

	var openidcookie = req.cookies['connect.sid'];
	if(openidcookie!=null){
		res.clearCookie("connect.sid");
		return res.redirect('https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=' + encodeURIComponent('http://localhost:3000/login'));
	}
	return res.redirect('/');
});

app.post("/register", (req, res) => {    
    const { username, password, password_conf, secure } = req.body
    
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

	scryptPbkdf.scrypt(password, salt, derivedKeyLength,ScryptParams).then(  // key is an ArrayBuffer
	  	function(key) { // key is an ArrayBuffer
		db.query('INSERT INTO users SET?', {name: username, password:  Buffer.from(key).toString('hex'), salt: Buffer.from(salt).toString('hex')}, (error, result) => {
		    if(error) {
		        console.log(error)
		    } else {
		        return res.redirect('/login');
		    }
		})
		},function(error) { console.log(error) })

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
      role: 'user', // just to show a private JWT field
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
