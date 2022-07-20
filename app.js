//jshint esversion:6
require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption')
const bcrypt = require('bcrypt')
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose') 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require( 'passport-facebook' ).Strategy;
const findOrCreate = require('mongoose-findorcreate')



const app = express()

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static('public'))

app.set('view engine', 'ejs')



app.use(session({
    secret: 'bananasmakegreatrockets...',
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())


mongoose.connect('mongodb://localhost:27017/secretsDB')

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId:String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:['password']})

const User = new mongoose.model('user', userSchema)

passport.use(User.createStrategy())

passport.serializeUser(function(user, done) {
    done(null, user.id); 
  
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/',(req,res)=>{
    res.render('home',{})
})


app.route('/register')
.get((req,res)=>{
    res.render('register',{})
})
.post((req,res)=>{
    const email = req.body.username
    const password = req.body.password

    User.register({username:email}, password, (err, user)=>{
        if(err){
            console.log(err)
            res.redirect('/register')
        }else{
            passport.authenticate('local')(req,res,()=>{
                res.redirect('/secrets')
            })
            
        }
    })

   
});

app.get('/secrets',(req,res)=>{
    if(req.isAuthenticated()){
        res.render('secrets')
    }else{
        res.redirect('/login')
    }
})

app.route('/login')
.get((req,res)=>{
    res.render('login',{})
})
.post((req,res)=>{
    const email = req.body.username
    const password = req.body.password

    const user = new User({
        email: email,
        password: password
    })

    req.login(user, (err)=>{
        if(err){
            console.log(err)
        }else{
            passport.authenticate('local')(req,res,()=>{
                res.redirect('/secrets')
            })
        }
    })
});

app.get('/logout', (req,res)=>{
    req.logout((err)=>{
        if(err){
            console.log(err)
        }else{
            res.redirect('/')
        }
    })
    
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.listen('3000',()=>{
    console.log('Server is running on localhost 3000')
})