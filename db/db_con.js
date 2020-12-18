const mariadb = require('mariadb/callback');
const config = require('./dbinfo').real;
module.exports = {
  init: function () {
    const con = mariadb.createConnection({
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database
    });
    con.connect(err => {
      if (err) {
        console.log("not connected due to error: " , err);
      } else {
        console.log("connected ! connection : " , config.host);
      }
    });
    return con ;
  },
}
