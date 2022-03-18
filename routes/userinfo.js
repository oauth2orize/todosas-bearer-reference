var express = require('express');
var passport = require('passport');
var HTTPBearerStrategy = require('passport-http-bearer');
var db = require('../db');


passport.use(new HTTPBearerStrategy(function verify(token, cb) {
  db.get('SELECT * FROM access_tokens WHERE value = ?', [
    token
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    var user = {
      id: row.user_id
    };
    // TODO: Pass scope as info
    return cb(null, user);
  });
}));


var router = express.Router();

router.get('/',
  passport.authenticate('bearer', { session: false }),
  function(req, res, next) {
    console.log('RETURN USER INFO');
    console.log(req.user);
    
    db.get('SELECT rowid AS id, username, name FROM users WHERE rowid = ?', [ req.user.id ], function(err, row) {
      if (err) { return next(err); }
    
      // TODO: Handle undefined row.
    
      var user = {
        sub: row.id.toString(),
        name: row.name,
        preferred_username: row.username
      };
      console.log('userinfo')
      console.log(user);
      
      res.json(user);
    });
    
  });

module.exports = router;
