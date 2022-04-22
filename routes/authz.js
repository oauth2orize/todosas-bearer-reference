var createError = require('http-errors');
var express = require('express');
var csrf = require('csurf');
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var url = require('url');
var db = require('../db');

var ensureLoggedIn = ensureLogIn();

function fetchClient(req, res, next) {
  var clientID = req.body.client_id || req.query.client_id;
  
  db.get('SELECT * FROM clients WHERE id = ?', [ clientID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return next(createError(400, 'Unknown client "' + clientID + '"')); }
    var client = {
      id: row.id,
      name: row.name
    };
    res.locals.client = client;
    next();
  });
}

function fetchGrant(req, res, next) {
  var grantID = req.params.grantID;
  
  db.get('SELECT * FROM grants WHERE id = ?', [ grantID ], function(err, row) {
    if (err) { return next(err); }
    if (!row) { return next(createError(400, 'Unknown grant "' + grantID + '"')); }
    var grant = {
      id: row.id,
      userID: row.user_id,
      clientID: row.client_id,
      scope: row.scope ? row.scope.split(' ') : null
    };
    res.locals.grant = grant;
    next();
  });
}

var router = express.Router();

router.get('/consent', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  res.render('consent', {
    user: req.user,
    scope: req.query.scope && req.query.scope.split(' '),
    action: url.parse(req.originalUrl).pathname,
    csrfToken: req.csrfToken()
  });
});

router.post('/consent', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  db.run('INSERT INTO grants (user_id, client_id, scope) VALUES (?, ?, ?)', [
    req.user.id,
    res.locals.client.id,
    req.body.scope
  ], function(err) {
    if (err) { return cb(err); }
    var grant = {
      id: this.lastID,
      scope: req.body.scope
    };
    var to;
    if (req.session.returnTo) {
      to = url.parse(req.session.returnTo, true);
      to.query.grant_id = grant.id;
      to.query.scope = grant.scope;
      delete to.search;
      to = url.format(to);
      delete req.session.returnTo;
    }
    return res.redirect(to || '/');
  });
});

router.get('/consent/:grantID', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  res.render('consent', {
    user: req.user,
    scope: req.query.scope && req.query.scope.split(' '),
    action: url.parse(req.originalUrl).pathname,
    csrfToken: req.csrfToken()
  });
});

router.post('/consent/:grantID', csrf(), ensureLoggedIn, fetchClient, function(req, res, next) {
  var client = res.locals.client;
  
  console.log('UPDATE EXISTING GRANT');
  
});

module.exports = router;
