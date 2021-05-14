"use strict";

const MAX_RESP_LEN = 1024 * 32;
const v_tcode = process.argv[2] ;
if (undefined == v_tcode ) {
  console.info("테스트ID를 지정하세요.") ;
  process.exit(1) ;
}

const mrdbc = require('./db/db_con');
const con = mrdbc.init();

const moment = require('moment');
const http = require('http');
moment.prototype.toSqlfmt = function () {
    return this.format('YYYY-MM-DD HH:mm:ss.SSSSSS');
};    

console.log("## Start send Data : ", v_tcode );

const sendhttp = require('./lib/sendHttp') ;

let param = { tcode : v_tcode, cond: (process.argv[3] ?  process.argv[3] : "" )
            , conn: con, limit:(process.argv[4] ?  process.argv[4] : "" ), interval: 0
            , func: () => { con.end() ; process.exit(0) ;} 
          } ;
sendhttp(param) ;

function endprog() {
    console.log("## program End");
    // child.kill('SIGINT') ;
    // con.end() ;
}

// process.on('SIGINT', process.exit(0) );
// process.on('SIGTERM', endprog() );
// process.on('uncaughtException', (err) => { console.log('uncaughtException:', err) ; process.exit } ) ;
// process.on('exit', endprog() );
