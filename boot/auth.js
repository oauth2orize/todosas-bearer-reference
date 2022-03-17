var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPassword = require('passport-oauth2-client-password');
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
  
  passport.use(new BasicStrategy(
    function(userid, password, done) {
      console.log('auth basic');
      console.log(userid);
      console.log(password);
    }
  ));
  
  passport.use(new OAuth2ClientPassword(
    function(clientId, clientSecret, cb) {
      console.log('auth client password');
      console.log(clientId);
      console.log(clientSecret);
      
      db.get('SELECT rowid AS id, secret, redirect_uri FROM clients WHERE rowid = ?', [ clientId ], function(err, row) {
        if (err) { return next(err); }
        if (!row) { return cb(null, false); }
        
        if (!crypto.timingSafeEqual(Buffer.from(row.secret), Buffer.from(clientSecret))) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
    
        var client = {
          id: row.id.toString(),
          secret: row.secret,
          redirectURI: row.redirect_uri
        };
        return cb(null, client);
      });
    }
  ));

};
