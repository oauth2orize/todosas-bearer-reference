var passport = require('passport');
var LocalStrategy = require('passport-local');
var BasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPassword = require('passport-oauth2-client-password');
var BearerStrategy = require('passport-http-bearer');
var crypto = require('crypto');
var db = require('../db');


module.exports = function() {

  // Configure the local strategy for use by Passport.
  //
  // The local strategy requires a `verify` function which receives the credentials
  // (`username` and `password`) submitted by the user.  The function must verify
  // that the password is correct and then invoke `cb` with a user object, which
  // will be set at `req.user` in route handlers after authentication.
  passport.use(new LocalStrategy(function(username, password, cb) {
    db.get('SELECT rowid AS id, * FROM users WHERE username = ?', [ username ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
      
      crypto.pbkdf2(password, row.salt, 10000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
        
        var user = {
          id: row.id.toString(),
          username: row.username,
          displayName: row.name
        };
        return cb(null, user);
      });
    });
  }));
  
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


  // Configure Passport authenticated session persistence.
  //
  // In order to restore authentication state across HTTP requests, Passport needs
  // to serialize users into and deserialize users out of the session.  The
  // typical implementation of this is as simple as supplying the user ID when
  // serializing, and querying the user record by ID from the database when
  // deserializing.
  passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });

  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

};
