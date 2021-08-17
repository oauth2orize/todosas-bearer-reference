var express = require('express');
var as = require('../as');
var db = require('../db');

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
  }),
  function(req, res, next) {
    console.log('TODO: authorize');
    console.log(req.oauth2)
  });

module.exports = router;
