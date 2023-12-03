if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const express = require ('express')
const app = express()
const bcrypt = require ('bcrypt')
const passport = require ('passport')
const initializePassport = require ('./passport-config')
const flash = require('express-flash')
const session = require('express-session')
app.use(express.static('public'));

initializePassport(passport, 
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
  )

// Do not use variables in production, should be stored in a database.
const users = []

app.set('view-engine', 'ejs')

app.use(flash());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(express.urlencoded({ extended: false }))

app.get('/', isAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name } )
})

// Login
app.post('/login', isNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/login', isNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

// Register
app.get('/register', isNotAuthenticated, (req, res) => {
  res.render('register.ejs')
})

app.post('/register', isNotAuthenticated, async (req, res) => {
  try {
    /* Encrypt the password with bcrypt adding a random salt in every password with 10 times security standard and stores in hasshedPassword variable
    8 For less secure
    10 For standard secure (enough for 99% of the projects)
    12 Or higher for super secure (hashes become slower but more secure)
    */
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    users.push({
      // Used date for example in production the database should auto generate a ID for you
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      // Send the salted password for the variable or the database in production
      password: hashedPassword
    })
    res.redirect('/login')
  } catch (error) {
    res.redirect('/register')
  }
  // See if users is added
  console.log(users)
})

function isAuthenticated (req, res, next) {
  if (req.isAuthenticated()){
    return next()
  }
  return res.redirect('/login')
}

function isNotAuthenticated (req, res, next) {
  if (req.isAuthenticated()){
    return res.redirect('/')
  }
  return next()
}

app.post('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/login'); // Redireciona o usuário para a página de login após o logout
  });
});

// Logout
app.delete('/logout', (req, res) => {
  req.logout(); // Passport.js fornece este método para deslogar o usuário
  res.redirect('/login'); // Redireciona o usuário para a página de login após o logout
});

app.listen(process.env.PORT)
console.log(`Application running on port http://localhost:${process.env.PORT}`)