const express = require('express');
const router = express.Router();

const {
    
    getLogin,
    postLogin,
    postLogout,
    postSignup,
    getSignup,
    getReset,
    postReset,
    getNewPassword,
    postNewPassword

} = require('../controllers/auth');

router.get('/login', getLogin);

router.get('/signup', getSignup);

router.get('/reset', getReset);

router.get('/reset/:token', getNewPassword);

router.post('/login', postLogin);

router.post('/signup', postSignup);

router.post('/logout', postLogout);

router.post('/reset', postReset);

router.post('/new-password', postNewPassword);

module.exports = router;