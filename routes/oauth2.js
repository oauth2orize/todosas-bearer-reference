var express = require('express');
var qs = require('querystring');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var crypto = require('crypto');
var db = require('../db');


var as = oauth2orize.createServer();

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
      if (err) { return cb(err); }
      return cb(null, code);
    });
  });
}));

as.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, cb) {
  console.log('TODO: code exchange');
  console.log(client);
  console.log(code);
  console.log(redirectURI);
  
  db.get('SELECT rowid AS id, * FROM authorization_codes WHERE code = ?', [
    code
  ], function(err, row) {
    console.log(err);
    console.log(row);
    
    if (err) { return next(err); }
    if (!row) { return cb(null, false); }
    
    crypto.randomBytes(64, function(err, buffer) {
      if (err) { return cb(err); }
    
      var token = buffer.toString('base64');
    
      db.run('INSERT INTO access_tokens (token, client_id, user_id) VALUES (?, ?, ?)', [
        token,
        row.client_id,
        row.user_id
      ], function(err) {
        if (err) { return cb(err); }
        return cb(null, token);
      });
    });
  });
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


function evaluate(client, user, scope, cb) {
  console.log('TODO: evaluate');
  console.log(client);
  console.log(user);
  console.log(scope);
  
  if (!user) { return cb(null, false, { prompt: 'login'} ); }
  
  console.log('DO WE HAVE CONSENT?');
  
  db.get('SELECT rowid AS id, * FROM grants WHERE user_id = ? AND client_id = ?', [
    user.id,
    client.id
  ], function(err, row) {
    console.log(err);
    console.log(row);
    
    if (err) { return next(err); }
    if (!row) { return cb(null, false, { prompt: 'consent' }); }
    
    var grant = {
      id: row.id.toString(),
      userID: row.user_id,
      clientID: row.client_id
    };
    return cb(null, true, { grant: grant });
  });
}

function prompt(req, res, next) {
  console.log('TODO: prompt');
  console.log(req.oauth2)
  console.log(req.oauth2.info);
  
  var prompt = req.oauth2.info.prompt;
  switch (prompt) {
  case 'login':
    return res.redirect('/login?' + qs.stringify({ state: req.oauth2.transactionID }));
  case 'consent':
    return res.redirect('/consent?' + qs.stringify({ client_id: req.oauth2.client.id, state: req.oauth2.transactionID }));
  }
}


var router = express.Router();

// http://localhost:3000/oauth2/authorize?response_type=code&client_id=1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth2%2Fredirect
router.get('/authorize', as.authorize(function(clientID, redirectURI, cb) {
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return cb(err); }
  
    // TODO: Handle undefined row.
  
    var client = {
      id: row.id.toString(),
      redirectURI: row.redirect_uri,
      name: row.name
    };
    if (client.redirectURI != redirectURI) { return cb(null, false); }
    return cb(null, client, client.redirectURI);
  });
}, evaluate), prompt);

router.get('/continue', as.resume(evaluate), prompt);

router.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  as.token(),
  as.errorHandler());

module.exports = router;
