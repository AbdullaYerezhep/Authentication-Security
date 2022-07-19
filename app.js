//jshint esversion:6
require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption')

const app = express()
mongoose.connect('mongodb://localhost:27017/secretsDB')

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
})

userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:['password']})

const User = new mongoose.model('user', userSchema)

app.use(bodyParser.urlencoded({extended:true}))
app.use(express.static('public'))

app.set('view engine', 'ejs')

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

    const newUser = new User({
        email: email,
        password: password
    })
    newUser.save((err)=>{
        if(err){
            res.send(err)
        }else{
            res.render('secrets')
        }
    })
});

app.route('/login')
.get((req,res)=>{
    res.render('login',{})
})
.post((req,res)=>{
    User.findOne({email:req.body.username},(err,foundUser)=>{
        if(err){
            res.send(err)
        }else{
            if(foundUser){
                if(foundUser.password === req.body.password){
                    res.render('secrets')
                }else{
                    res.send('The password or login is typed wrong')
                }
            }else{
                res.send('No such user was found')
            }
        }
    })
})


app.listen('3000',()=>{
    console.log('Server is running on localhost 3000')
})