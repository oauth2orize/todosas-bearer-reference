var createError = require('http-errors');
var express = require('express');
var oauth2orize = require('oauth2orize');
var passport = require('passport');
var HTTPBasicStrategy = require('passport-http').BasicStrategy;
var OAuth2ClientPasswordStrategy = require('passport-oauth2-client-password');
var async = require('async');
var url = require('url');
var qs = require('querystring');
var crypto = require('crypto');
var dateFormat = require('dateformat');


exports = module.exports = function(authzDB) {

function verify(clientID, clientSecret, cb) {
  authzDB.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
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
};

passport.use(new HTTPBasicStrategy(verify));
passport.use(new OAuth2ClientPasswordStrategy(verify));


var as = oauth2orize.createServer();

as.grant(oauth2orize.grant.code(function issue(client, redirectURI, user, ares, cb) {
  crypto.randomBytes(32, function(err, buffer) {
    if (err) { return cb(err); }
    var code = buffer.toString('base64');
    var expiresAt = new Date(Date.now() + 600000); // 10 minutes from now
    authzDB.run('INSERT INTO authorization_codes (client_id, redirect_uri, user_id, grant_id, scope, expires_at, code) VALUES (?, ?, ?, ?, ?, ?, ?)', [
      client.id,
      redirectURI,
      user.id,
      ares.grant.id,
      ares.scope.join(' '),
      dateFormat(expiresAt, 'yyyy-mm-dd HH:MM:ss', true),
      code
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, code);
    });
  });
}));

as.exchange(oauth2orize.exchange.code(function issue(client, code, redirectURI, cb) {
  var now = Date.now();
  authzDB.get('SELECT * FROM authorization_codes WHERE code = ?', [
    code
  ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false); }
    if (row.client_id !== client.id) { return cb(null, false); }
    if (row.redirect_uri !== redirectURI) { return cb(null, false); }
    if (Date.parse(row.expires_at + 'Z') <= now) { return cb(null, false); }
    
    crypto.randomBytes(64, function(err, buffer) {
      if (err) { return cb(err); }
      var accessToken = buffer.toString('base64');
      var expiresAt = new Date(Date.now() + 3600000); // 1 hour from now
      authzDB.run('INSERT INTO access_tokens (user_id, client_id, scope, expires_at, token) VALUES (?, ?, ?, ?, ?)', [
        row.user_id,
        row.client_id,
        row.scope,
        dateFormat(expiresAt, 'yyyy-mm-dd HH:MM:ss', true),
        accessToken,
      ], function(err) {
        if (err) { return cb(err); }
        
        crypto.randomBytes(64, function(err, buffer) {
          if (err) { return cb(err); }
          var refreshToken = buffer.toString('base64');
          var expiresAt = new Date(Date.now() + 2592000000); // 30 days from now
          authzDB.run('INSERT INTO refresh_tokens (grant_id, expires_at, token) VALUES (?, ?, ?)', [
            row.grant_id,
            dateFormat(expiresAt, 'yyyy-mm-dd HH:MM:ss', true),
            refreshToken,
          ], function(err) {
            if (err) { return cb(err); }
            
            authzDB.run('DELETE FROM authorization_codes WHERE code = ?', [
              code
            ], function(err) {
              if (err) { return cb(err); }
              return cb(null, accessToken, refreshToken, { expires_in: 3600 });
            });
          });
        });
      });
    });
  });
}));

as.grant(oauth2orize.grant.token(function issue(client, user, ares, cb) {
  var grant = ares.grant;
  
  crypto.randomBytes(64, function(err, buffer) {
    if (err) { return cb(err); }
    var token = buffer.toString('base64');
    authzDB.run('INSERT INTO access_tokens (user_id, client_id, token) VALUES (?, ?, ?)', [
      user.id,
      client.id,
      token,
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, token);
    });
  });
}));

as.serializeClient(function(client, cb) {
  process.nextTick(function() {
    cb(null, { id: client.id, type: client.type, name: client.name });
  });
});

as.deserializeClient(function(client, cb) {
  process.nextTick(function() {
    return cb(null, client);
  });
});


function evaluate(oauth2, cb) {
  oauth2.locals = oauth2.locals || {};
  
  async.waterfall([
    function login(next) {
      if (!oauth2.user) { return cb(null, false, oauth2.info, { prompt: 'login' } ); }
      next();
    },
    function allowed(next) {
      if (!oauth2.locals.grantID) { return next(); }
      
      authzDB.get('SELECT * FROM grants WHERE id = ?', [ oauth2.locals.grantID ], function(err, row) {
        if (err) { return next(err); }
        if (!row) { return next(createError(400, 'Unknown grant "' + oauth2.locals.grantID + '"')); }
        if (row.user_id !== oauth2.user.id) { return next(createError(403, 'Unauthorized grant "' + row.id + '" for user')); }
        if (row.client_id !== oauth2.client.id) { return next(createError(403, 'Unauthorized grant "' + row.id + '" for client')); }
        
        var grant = {
          id: row.id,
          scope: row.scope ? row.scope.split(' ') : null
        };
        return cb(null, true, { grant: grant, scope: oauth2.locals.scope });
      });
    },
    function consent(next) {
      if (oauth2.client.type !== 'confidential') { return cb(null, false, oauth2.info, { prompt: 'consent', scope: oauth2.req.scope } ); }
      if (oauth2.req.type !== 'code') { return cb(null, false, oauth2.info, { prompt: 'consent', scope: oauth2.req.scope } ); }
      
      authzDB.get('SELECT * FROM grants WHERE user_id = ? AND client_id = ?', [
        oauth2.user.id,
        oauth2.client.id
      ], function(err, row) {
        if (err) { return next(err); }
        if (!row) { return cb(null, false, oauth2.info, { prompt: 'consent', scope: oauth2.req.scope }); }
        
        var grant = {
          id: row.id,
          scope: row.scope ? row.scope.split(' ') : null
        };
        var addscope = oauth2.req.scope.filter(function(s) { return grant.scope.indexOf(s) == -1 });
        if (addscope.length > 0) {
          return cb(null, false, oauth2.info, { prompt: 'reconsent', grant: grant, scope: oauth2.req.scope });
        }
        return cb(null, true, { grant: grant, scope: oauth2.req.scope });
      });
    }
  ], function(err) {
    if (err) { return cb(err); }
    return cb(new Error('Internal authorization error'));
  });
}

function interact(req, res, next) {
  req.session.returnTo = url.resolve(req.originalUrl, 'continue?' +  qs.stringify({ transaction_id: req.oauth2.transactionID }));
  
  var prompt = req.oauth2.locals.prompt;
  var query = {};
  switch (prompt) {
  case 'login':
    return res.redirect('/login');
  case 'consent':
    query.client_id = req.oauth2.client.id;
    if (req.oauth2.locals.scope) {
      query.scope = req.oauth2.locals.scope.join(' ');
    }
    return res.redirect('/consent?' + qs.stringify(query));
  case 'reconsent':
    if (req.oauth2.locals.scope) {
      query.scope = req.oauth2.locals.scope.join(' ');
    }
    return res.redirect('/consent/' + req.oauth2.locals.grant.id + '?' + qs.stringify(query));
  default:
    return next(new Error('Unsupported prompt "' + prompt + '"'));
  }
}


var router = express.Router();

router.get('/authorize',
  as.authorize(function validate(clientID, redirectURI, cb) {
    authzDB.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(createError(400, 'Unknown client "' + clientID + '"')); }
      var client = {
        id: row.id,
        type: row.secret ? 'confidential' : 'public',
        name: row.name,
        redirectURI: row.redirect_uri
      };
      if (client.redirectURI !== redirectURI) { return cb(null, false); }
      return cb(null, client, client.redirectURI);
    });
  }, evaluate),
  interact,
  as.authorizationErrorHandler());

router.get('/continue',
  function(req, res, next) {
    res.locals.grantID = req.query.grant_id;
    res.locals.scope = req.query.scope ? req.query.scope.split(' ') : undefined;
    next();
  },
  as.resume(evaluate),
  interact,
  as.authorizationErrorHandler());

router.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  as.token(),
  as.errorHandler());

  return router;
};
