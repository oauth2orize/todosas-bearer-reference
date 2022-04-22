var createError = require('http-errors');
var express = require('express');
var url = require('url');
var qs = require('querystring');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var HTTPBasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPasswordStrategy = require('passport-oauth2-client-password');
var crypto = require('crypto');
var db = require('../db');


passport.use(new HTTPBasicStrategy(function verify(clientID, clientSecret, cb) {
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return cb(null, false); }
    if (!crypto.timingSafeEqual(Buffer.from(row.secret), Buffer.from(clientSecret))) {
      return cb(null, false);
    }
    var client = {
      id: row.id,
      name: row.name,
      redirectURI: row.redirect_uri
    };
    return cb(null, client);
  });
}));

passport.use(new OAuth2ClientPasswordStrategy(function verify(clientID, clientSecret, cb) {
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return cb(null, false); }
    if (!crypto.timingSafeEqual(Buffer.from(row.secret), Buffer.from(clientSecret))) {
      return cb(null, false);
    }
    var client = {
      id: row.id,
      name: row.name,
      redirectURI: row.redirect_uri
    };
    return cb(null, client);
  });
}));


var as = oauth2orize.createServer();

as.grant(oauth2orize.grant.code(function issue(client, redirectURI, user, ares, cb) {
  var grant = ares.grant;
  
  crypto.randomBytes(32, function(err, buffer) {
    if (err) { return cb(err); }
    var code = buffer.toString('base64');
    db.run('INSERT INTO authorization_codes (client_id, redirect_uri, user_id, grant_id, code) VALUES (?, ?, ?, ?, ?)', [
      client.id,
      redirectURI,
      user.id,
      grant.id,
      code
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, code);
    });
  });
}));

as.grant(oauth2orize.grant.token(function issue(client, user, ares, cb) {
  var grant = ares.grant;
  
  crypto.randomBytes(64, function(err, buffer) {
    if (err) { return cb(err); }
    var token = buffer.toString('base64');
    db.run('INSERT INTO access_tokens (user_id, client_id, token) VALUES (?, ?, ?)', [
      user.id,
      client.id,
      token,
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, token);
    });
  });
}));

as.exchange(oauth2orize.exchange.code(function issue(client, code, redirectURI, cb) {
  db.get('SELECT * FROM authorization_codes WHERE code = ?', [
    code
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    
    crypto.randomBytes(64, function(err, buffer) {
      if (err) { return cb(err); }
      var token = buffer.toString('base64');
      db.run('INSERT INTO access_tokens (user_id, client_id, token) VALUES (?, ?, ?)', [
        row.user_id,
        row.client_id,
        token,
      ], function(err) {
        if (err) { return cb(err); }
        return cb(null, token);
      });
    });
  });
}));

as.serializeClient(function(client, cb) {
  process.nextTick(function() {
    cb(null, { id: client.id, name: client.name });
  });
});

as.deserializeClient(function(client, cb) {
  process.nextTick(function() {
    return cb(null, client);
  });
});


function evaluate(client, user, scope, cb) {
  if (!user) { return cb(null, false, undefined, { prompt: 'login'} ); }
  
  db.get('SELECT * FROM grants WHERE user_id = ? AND client_id = ?', [
    user.id,
    client.id
  ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return cb(null, false, undefined, { prompt: 'consent' }); }
    var grant = {
      id: row.id,
      userID: row.user_id,
      clientID: row.client_id,
      scope: row.scope.split(' ')
    };
    return cb(null, true, { grant: grant });
  });
}

function interact(req, res, next) {
  req.session.returnTo = url.resolve(req.originalUrl, 'continue?' +  qs.stringify({ transaction_id: req.oauth2.transactionID }));
  
  var prompt = req.oauth2.locals.prompt;
  switch (prompt) {
  case 'login':
    return res.redirect('/login');
  case 'consent':
    return res.redirect('/consent?' + qs.stringify({ client_id: req.oauth2.client.id }));
  }
}


var router = express.Router();

// http://localhost:3000/oauth2/authorize?response_type=code&client_id=1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foauth2%2Fredirect
router.get('/authorize', as.authorize(function validate(clientID, redirectURI, cb) {
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(createError(400, 'Unknown client "' + clientID + '"')); }
    var client = {
      id: row.id,
      name: row.name,
      redirectURI: row.redirect_uri
    };
    if (client.redirectURI != redirectURI) { return cb(null, false); }
    return cb(null, client, client.redirectURI);
  });
}, evaluate), interact);

router.get('/continue', as.resume(evaluate), interact);

router.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  as.token(),
  as.errorHandler());

module.exports = router;
