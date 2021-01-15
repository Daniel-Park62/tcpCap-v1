const mariadb = require('mariadb');

module.exports = function () {
  const config = require('./dbinfo').real;
  const pool = mariadb.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: config.database,
    connectionLimit: 5
  });

  return {
   getConnection : async function() {
    try {
      console.log("start getconn");
      let conn = pool.getConnection();
      console.log("conn = " + conn); // { affectedRows: 1, insertId: 1, warningStatus: 0 }
      return conn;
    } catch (err) {
      console.log(err) ;
      throw err;
    }
    return null;
    },
    end : () => {
      pool.end();
    }
  }

}();
