var db = require('../db');


module.exports = function() {

  db.serialize(function() {
    db.run("CREATE TABLE IF NOT EXISTS users ( \
      username TEXT UNIQUE, \
      hashed_password BLOB, \
      salt BLOB, \
      name TEXT \
    )");
  });
  
  db.run("CREATE TABLE IF NOT EXISTS clients ( \
    secret TEXT NOT NULL, \
    redirect_uri TEXT NOT NULL, \
    name TEXT NOT NULL \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS grants ( \
    user_id INTEGER NOT NULL, \
    client_id INTEGER NOT NULL, \
    scope TEXT, \
    PRIMARY KEY (user_id, client_id) \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS authorization_codes ( \
    code TEXT UNIQUE NOT NULL, \
    client_id INTEGER NOT NULL, \
    redirect_uri TEXT NOT NULL, \
    user_id INTEGER NOT NULL, \
    scope TEXT \
  )");
  
  db.run("CREATE TABLE IF NOT EXISTS access_tokens ( \
    token TEXT UNIQUE NOT NULL, \
    client_id INTEGER NOT NULL, \
    user_id INTEGER NOT NULL, \
    scope TEXT \
  )");
  
  // TODO: Only do this if not exists
  db.run('INSERT INTO clients (secret, redirect_uri, name) VALUES (?, ?, ?)', [
    '7Fjfp0ZBr1KtDRbnfVdmIw',
    'http://localhost:3000/return',
    'My Example Client'
  ]);

  //db.close();

};
