var express = require('express');
var qs = require('querystring');
var passport = require('passport');
var db = require('../db');


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
