const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

// import express-session lib ***************************************8
const session = require('express-session');
const mongoStore = require('connect-mongodb-session')(session);
const csrf = require('csurf');

// error handling or to deliver some variable or message in the pre req
//  to the next req 
const flash = require('connect-flash');

const { mongoKey } = require('./config/key' )
const errorController = require('./controllers/error');
const User = require('./models/user');

const app = express();

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

const Mongo_URI = `mongodb+srv://joon:${mongoKey}@firstatlas-drwhc.mongodb.net/shop`;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

/* 
  // When session data is created.... in mongodb

  _id: "Sr5H66Ieud9JLHhUmymKb51iABX_yg_i"
  expires: 2019-03-20T19:42:39.295+00:00
  session: Object
  cookie: Object {
    originalMaxAge: null
    expires: null
    secure: null
    httpOnly: true
    domain: null
    path: "/"
    sameSite: null
  }
  isAuthenticated: true ==>>> we set it up  // set up by us

*/
// create collection to store session data including cookie
const store = new mongoStore({
  uri: Mongo_URI,
  collection: 'sessions'
});

// configuration to initialize. 
// We can confugure about cookie
// but default session would be fine
const csrfProtection = csrf();

// resave:false : as long as session data is not switched,
//  it is not going to be saved.
// saveUninitialized: false: until the req requests the session to be saved,
//  it is not going to be saved.
app.use(session({secret: 'asfasdfsafdsa', resave: false, saveUninitialized: false, store }));

// must use after session.
// because now we still use session to csrf attack
app.use(csrfProtection);

// if we want to hanle session message in connect-flash
// we need to put connect-flash at this spot.
app.use(flash());

// app.use((req, res, next) => {
//   // if(req.session.isAuthenticated) {
//     User.findById('5c7ff22830149705b40657f0')
//       .then(user => {
//         req.user = user
//       });
//   //}
// });

// moved to login route
app.use((req, res, next) => {

  if(req.session.user) {

    // We can get req.session.user._id only when user logged in 
    //  stores the session data in db.
    //  Therefore, we do not need to get req.session.isAuthenticated.
      User.findById(req.session.user._id)
        .then(user => {
          req.user = user;
          next();
        })
        .catch(err => console.log(err));
  } else {
    next();
  }
  
});

// Therefore every req is executed , the following value will reach to view's render.
app.use((req, res, next) => {
  // locals: it is built in method express
  // to make variables and deliver variable value to local 'views'
  // It is able to deliver the value withou saparately from 'res.render()'.
  // Then, it is often used to deliver common value.
  res.locals.isAuthenticated = req.session.isAuthenticated;
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.use(errorController.get404);

mongoose
  .connect(Mongo_URI, { useNewUrlParser: true })
  .then(() => {
    console.log('Server is up!');
    app.listen(3000);
  })
  .catch(err => {
    console.log(err);
  });
