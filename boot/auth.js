var passport = require('passport');
var BearerStrategy = require('passport-http-bearer');
var crypto = require('crypto');
var db = require('../db');


module.exports = function() {
  
  passport.use(new BearerStrategy(
    function(token, cb) {
      console.log('auth bearer');
      console.log(token);
      
      db.get('SELECT * FROM access_tokens WHERE token = ?', [
        token
      ], function(err, row) {
        console.log(err);
        console.log(row);
      
        if (err) { return next(err); }
        if (!row) { return cb(null, false); }
      
        var user = {
          id: row.user_id.toString()
        };
        // TODO: Pass scope as info
        return cb(null, user);
      });
    }
  ));

};
