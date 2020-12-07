var express = require('express');
var router = express.Router();
const argon2 = require('argon2');
var QRCode = require('qrcode');

var mongo = require('mongodb');
// Connection URI
const uri =
  "mongodb://localhost:27017/actseg?poolSize=20&w=majority";
// Create a new MongoClient
const client = new mongo.MongoClient(uri,{useUnifiedTopology: true});
const Speakeasy = require("speakeasy");

/* GET home page. */
router.get('/', async function(req, res, next) {
  if(req.session.uid && req.session.auth){
    await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    var o_id = new mongo.ObjectID(req.session.uid);
    const userQuery = { _id: o_id};
    let user = await collection.findOne(userQuery);
    user.lastlogindate= new Date(user.lastlogin).toISOString();
    return res.render("index",{user})
  }
  return res.redirect("/login")
});

router.post('/', async function(req, res, next) {
  await client.connect();
  const database = client.db("actseg");
  const collection = database.collection("users");
  var o_id = new mongo.ObjectID(req.session.uid);
  const userQuery = { _id: o_id};
  let user = await collection.findOne(userQuery);
  console.log(user);
  if(!req.body.name){
    msg="ingresa el nombre"
    return  res.redirect("/");
  }
  user.name = req.body.name;
  await collection.save(user);
  user.lastlogindate= new Date(user.lastlogin).toISOString();
  return  res.render("index",{user,msg});
});

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.get('/register', function(req, res, next) {
  res.render('register');
});

router.get('/logout', function(req, res, next) {
  req.session.destroy();
  res.redirect('/login');
});

router.get('/2fa-setup', async function(req, res, next) {
  if(!req.session.uid){
    res.redirect("/login");
  }
  else{
   genCode(req,res);
  }
});

let genCode = async (req,res)=>{
  let secret = Speakeasy.generateSecret({ length: 20 });
  req.session.otpkey = secret.base32;
  let uri = secret.otpauth_url;
  let qr = await QRCode.toDataURL(uri);
  return res.render('2fa-setup',{msg,qr});
}

router.post('/2fa-setup', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  if(!req.body.otp){
    msg="ingresa el codigo"
    return genCode(req,res);
  }
  if(req.body.otp.length != 6){
    msg="el codigo debe ser de 6 digitos"
    return genCode(req,res);
  }
  let otpkey = req.session.otpkey;
    let validcode =  Speakeasy.totp.verify({
      secret: otpkey,
      encoding: "base32",
      token: req.body.otp,
      window: 0
    });
    if(validcode){
      const database = client.db("actseg");
      const collection = database.collection("users");
      var o_id = new mongo.ObjectID(req.session.uid);
      const userQuery = { _id: o_id};
      let user = await collection.findOne(userQuery);
      req.session.auth=true;
      user["otp-key"]=req.session.otpkey
      req.session.otpkey = null;

      await collection.save(user);
      return res.redirect("/");
    }
    else{
      msg="codigo invalido"
      return genCode(req,res);
    }
});

router.get('/2fa', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  res.render("2fa-login");
});



router.post('/2fa', async function(req, res, next) {
  if(!req.session.uid){
    return res.redirect("/login");
  }
  if(!req.body.otp){
    msg="ingresa el codigo"
    return  res.render("2fa-login",{msg});
  }
  if(req.body.otp.length != 6){
    msg="el codigo debe ser de 6 digitos"
    return  res.render("2fa-login",{msg});
  }
  await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    var o_id = new mongo.ObjectID(req.session.uid);
    const userQuery = { _id: o_id};
    let user = await collection.findOne(userQuery);
  let otpkey = user["otp-key"];
    let validcode =  Speakeasy.totp.verify({
      secret: otpkey,
      encoding: "base32",
      token: req.body.otp,
      window: 0
    });
    if(validcode){
      req.session.auth = true;
      user.lastlogin = Date.now();
      await collection.save(user);
      return res.redirect("/");
    }
    else{
      console.log("OK")
      msg="codigo invalido"
      return  res.render("2fa-login",{msg});
    }
});

router.post('/login', async function(req, res, next) {
  msg=null;
  if(!req.body.username || !req.body.password){
    msg="Faltan datos";
    return res.render('login',{msg});
  }
  await client.connect();
  const database = client.db("actseg");
  const collection = database.collection("users");
  const userQuery = { username: req.body.username };

  let user = await collection.findOne(userQuery);

  if(!user){
    msg="Datos incorrectos";
    return res.render('login',{msg});
  }
  const hashedPw =  user.password;
  let valid =  await argon2.verify(hashedPw,req.body.password)
  if(!valid){
    msg="Datos incorrectos";
    return res.render('login',{msg});
  }
  else{
    req.session.uid=user._id;
    if(user["otp-key"]==""){
      res.redirect("/2fa-setup")
    }
    else{
      res.redirect("/2fa")
    }
  }
});


router.post('/register', async function(req, res, next) {
  msg=null;
  if(!req.body.username || !req.body.password || !req.body.name){
    msg="Faltan datos";
  }
  else{
    await client.connect();
    const database = client.db("actseg");
    const collection = database.collection("users");
    const userQuery = { username: req.body.username };

    let user = await collection.findOne(userQuery);

    if(user){
      msg="El usuario ya existe";
    }
    else{
      const hashedPw = await argon2.hash(req.body.password);
      let newUser = {
          "username":req.body.username,
          "password":hashedPw,
          "name":req.body.name,
          "lastlogin":0, 
          "otp-key":""
      }
      const result = await collection.insertOne(newUser);
      if(result.insertedCount==1){
       msg="Usuario registrado" 
      }
    }
  }
  res.render('register',{msg});
});


module.exports = router;
