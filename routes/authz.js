var createError = require('http-errors');
var express = require('express');
var csrf = require('csurf');
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');

var ensureLoggedIn = ensureLogIn();

function fetchClient(req, res, next) {
  var clientID = req.body.client_id || req.query.client_id;
  
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return next(createError(400, 'Unknown client "' + req.query.client_id + '"')); }
    var client = {
      id: row.id,
      name: row.name
    };
    res.locals.client = client;
    next();
  });
}


var router = express.Router();

router.get('/consent', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  res.render('consent', { user: req.user, csrfToken: req.csrfToken() });
});

router.post('/consent', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  var client = res.locals.client;
  
  db.get('SELECT * FROM grants WHERE user_id = ? AND client_id = ?', [
    req.user.id,
    client.id
  ], function(err, row) {
    if (err) { return next(err); }
    if (!row) {
      db.run('INSERT INTO grants (user_id, client_id, scope) VALUES (?, ?, ?)', [
        req.user.id,
        client.id,
        'profile email'
      ], function(err) {
        if (err) { return next(err); }
        var grant = {
          id: this.lastID
        };
        var url = '/';
        if (req.session.returnTo) {
          url = req.session.returnTo;
          delete req.session.returnTo;
        }
        return res.redirect(url);
      });
    } else {
      console.log('UPDATE THE GRANT');
      console.log(row);
    }
  });
});

module.exports = router;
