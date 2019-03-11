
const bcrypt = require('bcryptjs');

// crypto is a built-in lib in node.js (not third part lib);
// It will be used to ceate a token in password reset.
const crypto = require('crypto');

// import sendgrid with node mailer
// created Third party mail server
const nodeMailer = require('nodemailer');
// provided sendgrid api server out of many mail appss registered for nodemailer
const sendgridTransport = require('nodemailer-sendgrid-transport');

const { seng_grid } = require('../config/key');
// nodemailer encloses integrate / encloses sendgrid
const transporter = nodeMailer.createTransport(sendgridTransport({
    auth: {
        // api_user: ,
        api_key: seng_grid
    }
}));

const User = require('../models/user');

exports.getLogin = (req, res, next) => {

  let message = req.flash('error');
  message = message.length === 0 ? null : message[0];

  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message
  });
};

exports.getSignup = (req, res, next) => {

    let message = req.flash('error');
    message = message.length === 0 ? null : message[0];

  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message
   // isAuthenticated: false
  });
};

exports.postLogin = (req, res, next) => {

    const { email, password } = req.body;
    User.findOne({ email })
        .then(user => {
            if(!user) { 

                req.flash('error', 'Invalid email');
                return res.redirect('/login'); 
            }

            bcrypt.compare(password, user.password)

                .then(isMatched => {
                    // ************ here we can initilize session!!!!!
                    if(isMatched) { 

                        req.session.isAuthenticated = true;
                        req.session.user = user;
                        return req.session.save(err => {
                            res.redirect('/');
                        });
                    
                    }
                    // must be spotted res.redirect
                    req.flash('error', 'Invalid password');

                    // isMatched === false
                    res.redirect('/login');
                    
                })
                .catch(e => { 
                    // we can setup redirect in catch block.
                    res.redirect('/login');
                    throw new Error('Unable to find the password.');
                });
            
        })

};

exports.postSignup = (req, res, next) => {
    const { email, password, confirmPassword } = req.body;

    User.findOne({ email })
        .then(user => {

            // Therefore
            if(user) {
                // must be spotted at upperline of res.redirect
                req.flash('error', 'Email exists arleady.');
                return res.redirect('/signup');
            }
            
            bcrypt.hash(password, 12)
                .then(hashedPassword => {

                    const newUser = new User({
                        email,
                        password: hashedPassword,
                        cart: { items: [] }
                    });
        
                    return newUser.save();
        
                })
                .then(() => {

                    // 2) to show error message, just in case
                    res.redirect('/login');

                    // Adding sending confirmation email
                    // async
                    return transporter.sendMail({
                        // setup receiver
                        to: email, // signup user
                        from: 'shop@node-complete.com',
                        subject: 'Signup succeeded!',
                        html: '<h1>You successfully signed up</h1>'

                    })
                    .catch(e => { throw new Error('Failed to send email!'); });
                    
                    // It is ok, btw. ***************************************888
                    // However, it is really important
                    //  that because of async, the user should wait 
                    //  for callback invoked and executed.
                    // It can have the performance lagged.
                    // So if the functions are not associated with
                    //  certain orders, it should be in the last process / step.

                    
                    // transporter.sendMail({
                    //     // setup receiver
                    //     to: email, // signup user
                    //     from: 'shop@node-complete.com',
                    //     subject: 'Signup succeeded!',
                    //     html: '<h1>You successfully signed up</h1>'

                    // })
                    // res.redirect('/login');
                
                })
                // catch!!!! : only when promise is used!!!
                .catch(e => {
                    throw new Error('The email already exists.');
                });

        })
        
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

// token!!!
exports.getReset = (req, res, next) => {
    let message = req.flash('error');
    if(message.length === 0) {
        message = null;
    } else {
        message = message[0];
    }
    res.render('auth/reset', {
        path: '/reset',
        pageTitle: 'Reset Password',
        errorMessage: message
    });
}

// it is for password reset button
exports.postReset = (req, res, next) => {
    // randomBytes: creating encrypted token
    crypto.randomBytes(32, (err, buffer) => {
        if(err) {
            console.log(err);
            return res.redirect('/reset');
        }
        // get token from buffer which is return value of randomBytes
        // *******************************************************************8
        // The reason token is required is because loggein user
        //      is able to get 'reset' page by using url.
        // Then, they can get to password update page without email verification
        //  and token verification. Only the user get email and token verification
        //  can change the password.!!!

        const token = buffer.toString('hex');
        // from email form
        User.findOne({ email: req.body.email })
            .then(user => {
                if(!user) {
                    req.flash('error', 'No account with that email.');
                    return res.redirect('/reset');
                }

                user.resetToken = token;
                // 360000 (+ an hour) : the token is expired within an hour.
                //  Therefore, the user must renew the password in an hour.
                user.resetTokenExpiry = Date.now() + 3600000;
                return user.save();

            })
            .then(() => {

                res.redirect('/');

                transporter.sendMail({
                    // setup receiver
                    to: req.body.email,
                    from: 'shop@node-complete.com',
                    subject: 'Password Reset',
                    html: `
                        <p>You requested a password reset.</p>
                        <p>Click this <a href="http://localhost:3000/reset/${token}">link.</a> to set a new password.</p>`

                });
            })
            .catch(e => { throw new Error('Unable to reset your password reset token.'); });

    });
}

exports.getNewPassword = (req, res, next) => {
    // verifying the resetToken is available.
    const { token } = req.params;

    // { $gt: Date.now() } : restTokenExpiry is greater than now (if expiry date is in the future)
    //  because the token controls the user must renew password in a limited period of time.
    //      when the token is created.
    User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } })
        .then(user => {
            let message = req.flash('error');
            if(message.length === 0) {
                message = null;
            } else {
                message = message[0];
            }
            res.render('auth/new-password', {
                path: 'new-password',
                pageTitle: 'New Password',
                errorMessage: message,
                passwordToken: token,
                // in order to find the user when the user renews the password.
                userId: user._id.toString()
            });

        }).catch(e =>{ throw new Error('You are not allowed to reset the password.'); });

}

exports.postNewPassword = (req, res, next) => {
    // userId is hidden, by the way.
    const { password, userId, passwordToken } = req.body;
    let resettingUser;

    User.findOne({ 
        _id: userId, 
        resetToken: passwordToken,
        resetTokenExpiry: { $gt: Date.now() }
    })
    .then(user => {
        if(!user) {
            req.flash('error', 'No account with that give token.');
            return res.redirect('/login');
        }
        resettingUser = user;
        return bcrypt.hash(password, 12);
    })
    .then(newPassword => {
        resettingUser.password = newPassword;
        // remove the schema fields ***************************************
        // "undefine!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        resettingUser.resetToken = undefined;
        resettingUser.resetTokenExpiry = undefined;
        return resettingUser.save();
    })
    .then(() => {
        res.redirect('/login');
    })
    .catch(e => { throw new Error('Unable to find the user with that given token.'); });    

}