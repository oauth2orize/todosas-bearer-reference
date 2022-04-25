var createError = require('http-errors');
var express = require('express');
var passport = require('passport');
var HTTPBearerStrategy = require('passport-http-bearer');
var db = require('../db');


passport.use(new HTTPBearerStrategy(function verify(token, cb) {
  var now = Date.now();
  db.get('SELECT * FROM access_tokens WHERE token = ?', [
    token
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    if (Date.parse(row.expires_at + 'Z') <= now) { return cb(null, false); }
    
    var user = {
      id: row.user_id
    };
    var authInfo = {
      scope: row.scope ? row.scope.split(' ') : []
    };
    return cb(null, user, authInfo);
  });
}));


var router = express.Router();

router.get('/userinfo', passport.authenticate('bearer', { session: false, failWithError: true }), function(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [ req.user.id ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return next(createError(403)); }
    var info = {
      sub: row.id.toString()
    };
    if (req.authInfo.scope.indexOf('profile') != -1) {
      if (row.name) { info.name = row.name; }
      if (row.username) { info.preferred_username = row.username; }
    }
    if (req.authInfo.scope.indexOf('email') != -1) {
      if (row.email) { info.email = row.email; }
      if (row.email_verified) { info.email_verified = row.email_verified; }
    }
    if (req.authInfo.scope.indexOf('phone') != -1) {
      if (row.phone_number) { info.phone_number = row.phone_number; }
      if (row.phone_number_verified) { info.phone_number_verified = row.phone_number_verified; }
    }
    res.json(info);
  });
}, function(err, req, res, next) {
  res.status(err.status || 500);
  return res.end();
});

module.exports = router;
