var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');
var crypto = require('crypto');

mkdirp.sync('var/db');

var db = new sqlite3.Database('var/db/users.db');

db.serialize(function() {

  db.run("CREATE TABLE IF NOT EXISTS users ( \
    username TEXT UNIQUE, \
    hashed_password BLOB, \
    salt BLOB, \
    name TEXT \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS clients ( \
    secret TEXT, \
    name TEXT NOT NULL, \
    redirect_uri TEXT \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS grants ( \
    user_id INTEGER NOT NULL, \
    client_id INTEGER NOT NULL, \
    scope TEXT, \
    PRIMARY KEY (user_id, client_id) \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS authorization_codes ( \
    client_id INTEGER NOT NULL, \
    redirect_uri TEXT, \
    user_id INTEGER NOT NULL, \
    scope TEXT, \
    expires_at DATETIME, \
    value TEXT UNIQUE NOT NULL \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS access_tokens ( \
    user_id INTEGER NOT NULL, \
    client_id INTEGER NOT NULL, \
    scope TEXT, \
    expires_at DATETIME, \
    token TEXT UNIQUE NOT NULL \
  )");
  
  // create an initial user (username: alice, password: letmein)
  var salt = crypto.randomBytes(16);
  db.run('INSERT OR IGNORE INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
    'alice',
    crypto.pbkdf2Sync('letmein', salt, 310000, 32, 'sha256'),
    salt
  ]);
  
  // TODO: Only do this if client does not already exist
  db.run('INSERT OR IGNORE INTO clients (secret, redirect_uri, name) VALUES (?, ?, ?)', [
    '7Fjfp0ZBr1KtDRbnfVdmIw',
    'http://localhost:3000/return',
    'My Example Client'
  ]);

});

module.exports = db;
