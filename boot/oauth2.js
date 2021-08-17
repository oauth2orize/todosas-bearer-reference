var oauth2orize = require('oauth2orize');
var as = require('../as');


module.exports = function() {

  as.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    console.log('TODO: code grant');
    console.log(code);
    console.log(redirectURI)
  }));
  
  as.serializeClient(function(client, cb) {
    process.nextTick(function() {
      cb(null, {
        id: client.id,
        name: client.name
      });
    });
  });

};
