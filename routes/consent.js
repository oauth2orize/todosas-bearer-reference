var express = require('express');
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

module.exports = router;
