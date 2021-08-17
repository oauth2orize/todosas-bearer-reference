var oauth2orize = require('oauth2orize');
var crypto = require('crypto');
var as = require('../as');
var db = require('../db');


module.exports = function() {

  as.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, cb) {
    console.log('TODO: code grant');
    console.log(client);
    console.log(redirectURI);
    console.log(user);
    console.log(ares);
    
    crypto.randomBytes(32, function(err, buffer) {
      if (err) { return cb(err); }
      
      var code = buffer.toString('base64');
      
      db.run('INSERT INTO authorization_codes (code, client_id, redirect_uri, user_id) VALUES (?, ?, ?, ?)', [
        code,
        client.id,
        redirectURI,
        user.id
      ], function(err) {
        if (err) { return next(err); }
        return cb(null, code);
      });
    });
  }));
  
  as.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, cb) {
    console.log('TODO: code exchange');
    console.log(client);
    console.log(code);
    console.log(redirectURI);
    
    return cb(null, '3foe3');
  }));
  
  as.serializeClient(function(client, cb) {
    process.nextTick(function() {
      cb(null, {
        id: client.id,
        name: client.name
      });
    });
  });
  
  as.deserializeClient(function(client, cb) {
    process.nextTick(function() {
      return cb(null, client);
    });
  });

};
