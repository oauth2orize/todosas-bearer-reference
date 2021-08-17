var express = require('express');
var qs = require('querystring');
var as = require('../as');
var db = require('../db');


function evaluate(client, user, scope, cb) {
  console.log('TODO: evaluate');
  console.log(client);
  console.log(user);
  console.log(scope);
  
  if (!user) { return cb(null, false, { prompt: 'login'} ); }
  
  
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
  function(req, res, next) {
    console.log('TODO: authorize');
    console.log(req.oauth2)
    console.log(req.oauth2.info);
    
    var prompt = req.oauth2.info.prompt;
    switch (prompt) {
    case 'login':
      return res.redirect('/login?' + qs.stringify({ state: req.oauth2.transactionID }));
    }
  });

router.get('/continue', as.resume(evaluate),
  function(req, res, next) {
    console.log('TODO: continue');
    console.log(req.oauth2)
    console.log(req.oauth2.info);
    
    /*
    var prompt = req.oauth2.info.prompt;
    switch (prompt) {
    case 'login':
      return res.redirect('/login?' + qs.stringify({ state: req.oauth2.transactionID }));
    }
    */
  });

module.exports = router;
