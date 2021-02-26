const mariadb = require('mariadb');
const config = require('./dbinfo').real;
module.exports.init =  function () {
    let conn ;
    mariadb.createConnection({
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database
    })
    .then(con => conn = con)
    .catch(err => console.log(err));

    return conn ;

} ;
