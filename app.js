require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//Express-session module setup
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

//Passport and mongoDB ATLAS setup
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb+srv://henry:123@cluster0.807wml5.mongodb.net/userDB');


//Mongoose Schema setup
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//Passport setup serialize and deserialize
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


//Google Auth API
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://authentication-rp1h.onrender.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//Home route
app.get('/', function(req, res) {
  res.render('home');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

//Google authentication
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/login', function(req, res) {
  res.render('login');
});

app.get('/register', function(req, res) {
  res.render('register');
});


//Finds all users with secrets and passes them to be rendered in /secrets
app.get('/secrets', function(req, res) {
  User.find({'secret': {$ne: null}}).then(function(foundUsers, err){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render('secrets', {usersWithSecrets: foundUsers})
      }
    }
  });
});


//Checks to see if user is authenticated before accessing /submit
app.get('/submit', function(req, res){
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});


//Saves what was typed as the user's secret and redirects to /secrets
app.post('/submit', function(req, res){
  const submitedSecret = req.body.secret;

  User.findById(req.user.id).then(function(foundUser, err){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submitedSecret;
        foundUser.save().then(function(){
          res.redirect('/secrets');
        });
      }
    }
  });
});


//Logs out (??
app.get('/logout', function(req, res) {
  req.logout(function(err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/');
    }
  });
});


//Local registering with passport
app.post('/register', function(req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect('/');
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('secrets');
      });
    }
  });
});


//Logs user
app.post('/login', function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('/secrets');
      });
    }
  });
});




//Server port
app.listen(process.env.PORT || 3000, function() {
  console.log('WORKING');
});
