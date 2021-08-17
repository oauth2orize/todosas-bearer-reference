var express = require('express');
var qs = require('querystring');
var passport = require('passport');
var as = require('../as');
var db = require('../db');


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

router.get('/authorize',
  as.authorize(function(clientID, redirectURI, cb) {
    db.get('SELECT rowid AS id, redirect_uri, name FROM clients WHERE rowid = ?', [ clientID ], function(err, row) {
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
  }, evaluate),
  prompt);

router.get('/continue', as.resume(evaluate), prompt);

router.post('/token',
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  as.token(),
  as.errorHandler());

module.exports = router;
