//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const googleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const CRYPTR = require(__dirname + '/crypto.js');
const cryptr = new CRYPTR(process.env.ENCRYPTION_KEY)

const app = express();
 
app.use(express.static("public"));
app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'Secret', 
  resave: false, 
  cookie: {},
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const uri = 'mongodb+srv://farhan_19:'+process.env.MONGO_PASSWORD+'@secrets.bm41s.mongodb.net/?retryWrites=true&w=majority';

mongoose
     .connect( uri)
     .then(() => console.log( 'Database Connected' ))
     .catch(err => console.log( err ));

const userSchema = new mongoose.Schema({
    email: String, 
    password: String,
    googleId: String,
    secret: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new googleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "https://www.sleepy-fjord-47035.herokuapp.com/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


//GET ROUTES
 
app.get("/", (req, res) => {
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
   // Successful authentication, redirect to secrets page.
   res.redirect('/secrets');
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/secrets", (req, res) => {
  // The below line was added so we can't display the "/secrets" page
  // after we logged out using the "back" button of the browser, which
  // would normally display the browser cache and thus expose the 
  // "/secrets" page we want to protect.
  res.set(
    'Cache-Control', 
    'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
  );
  
  User.find({"secrets": {$ne: null}}, function (err, foundUsers) {
    if(err) {
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers, CRYPTR: cryptr});
      }
    }
  });
});

app.get("/logout", (req, res) => {
  req.logout(function(err) {
    if(err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
  
});

app.get("/submit", (req, res) => {
  if(req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//POST ROUTES

app.post("/register", (req, res) => {
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
  
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser) {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret.push(cryptr.encrypt(submittedSecret));
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});


let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
    console.log('Server has started');
});