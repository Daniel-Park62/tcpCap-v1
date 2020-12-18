module.exports = {
    local: { // localhost
      host: process.env.DBIP  || 'localhost',
      port: '3306',
      user: 'aqtdb',
      password: 'Dawinit1!',
      database: 'aqtdb2'
    },
    real: { // real server db info
      host: process.env.DBIP  || 'localhost',
      port: '3306',
      user: 'aqtdb',
      password: 'Dawinit1!',
      database: 'aqtdb2'
    },
    dev: { // dev server db info
      host: process.env.DBIP  || 'localhost',
      port: '3306',
      user: 'aqtdb',
      password: 'Dawinit1!',
      database: 'aqtdb2'
    }
  };
