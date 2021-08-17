var oauth2orize = require('oauth2orize');
var as = require('../as');


module.exports = function() {

  as.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, cb) {
    console.log('TODO: code grant');
    console.log(client);
    console.log(redirectURI);
    console.log(user);
    console.log(ares);
    
    return cb(null, '2yotn');
  }));
  
  as.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, cb) {
    console.log('TODO: code exchange');
    console.log(client);
    console.log(code);
    console.log(redirectURI);
    
    return cb(null, '3foe3');
  }));
  
  as.serializeClient(function(client, cb) {
    process.nextTick(function() {
      cb(null, {
        id: client.id,
        name: client.name
      });
    });
  });
  
  as.deserializeClient(function(client, cb) {
    process.nextTick(function() {
      return cb(null, client);
    });
  });

};
