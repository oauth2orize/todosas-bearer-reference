var express = require('express');
var qs = require('querystring');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');

var router = express.Router();

/* GET users listing. */
router.get('/',
  ensureLoggedIn(),
  function(req, res, next) {
    db.get('SELECT rowid AS id, redirect_uri, name FROM clients WHERE rowid = ?', [ req.query.client_id ], function(err, row) {
      if (err) { return cb(err); }
    
      // TODO: Handle undefined row.
    
      var client = {
        id: row.id.toString(),
        name: row.name
      };
      res.render('consent', { user: req.user, client: client, state: req.query.state });
    });
  });

router.post('/',
  function(req, res, next) {
    console.log('CREATE GRANT');
    console.log(req.user);
    console.log(req.body);
  
    db.run('INSERT INTO grants (user_id, client_id) VALUES (?, ?)', [
      req.user.id,
      req.body.client_id
    ], function(err) {
      if (err) { return next(err); }
      
      var grant = {
        id: this.lastID.toString(),
        userID: req.user.id,
        clientID: req.body.client_id
      };
      
      console.log('CREATED GRANT!');
      console.log(grant);
      
      if (req.body.state) {
        return res.redirect('/oauth2/continue?'+ qs.stringify({ transaction_id: req.body.state }));
      }
    });
  });

module.exports = router;
