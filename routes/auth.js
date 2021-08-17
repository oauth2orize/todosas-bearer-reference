var express = require('express');
var qs = require('querystring');
var passport = require('passport');

var router = express.Router();

/* GET users listing. */
router.get('/login', function(req, res, next) {
  res.render('login', { state: req.query.state });
});

router.post('/login/password', passport.authenticate('local', {
  failureRedirect: '/login',
  failureMessage: true
}), function(req, res, next) {
  if (req.body.state) {
    return res.redirect('/oauth2/continue?'+ qs.stringify({ transaction_id: req.body.state }));
  }
  res.redirect('/');
});

router.get('/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

module.exports = router;
