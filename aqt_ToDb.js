"use strict";

const CN_TCODE = process.argv[2];
const dstv = process.argv[3];
if (undefined == dstv) {
    console.info("대상 파일(또는 host)을 지정하세요.");
    console.info("aqtCapTodb 호스트(파일) 테스트id");
    process.exit(1);
}
if (undefined == CN_TCODE) {
    console.info("저장될 테스트ID를 지정하세요.");
    console.info("aqtCapTodb 호스트(파일) 테스트id");
    process.exit(1);
}
// let myMap = new Map();
// const { resolve } = require('path');
const mysql_dbc = require('./db/db_con');
const con = mysql_dbc.init();

// con.query("SELECT COUNT(*) AS cnt FROM TMASTER WHERE CODE = ?", [CN_TCODE],
// (err, dat) => {
//   if (!err) {
//     if (dat[0].cnt == 0) {
//       console.info("테스트ID 를 확인하세요. => ", CN_TCODE) ;
//       con.end ;
//       process.exit(1) ;
//     }
//   } else {
//       console.error(err) ;
//       con.end ;
//       process.exit(1) ;
//   }
// } ) ;

console.info(process.argv[2], CN_TCODE);
process.on('SIGINT', process.exit);
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err); process.exit });
// process.on('exit', endprog);
const cdb = require('./lib/capToDb_tcp') ;
// new cdb( {p_tcode:CN_TCODE, dstv:dstv, p_type:"F", p_dstip:"211.241.100.111" , pfunc : () => { console.log('melong');} } ) ;
new cdb( {p_tcode:CN_TCODE, dstv:dstv, p_type:"F", p_dstip:"118.42.5.83" , pfunc : () => { console.log('melong');} } ) ;
