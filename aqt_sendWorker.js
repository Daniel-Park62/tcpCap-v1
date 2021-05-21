"use strict";

const mrdb = require('./db/db_con');
const con = mrdb.init() ;

const PGNM = '[sendWorker]';

const  { parentPort, threadId,  workerData } = require('worker_threads');

console.log("## Start send Data threadId : ",threadId );

const sendhttp = require('./lib/sendHttp') ;

// const {tcode, cond, dbskip, interval, limit, loop } = workerData ;
let param = workerData ;

console.log(param);

param.conn = con ;
param.func = () => { 
  param.conn.end();
  parentPort.close();
  console.log(PGNM + "%s ## (%d) End",param.tcode, threadId); 
  // process.exit(0) ;
} ;

// let param = { tcode : tcode, cond: cond, conn: con, dbskip:dbskip, limit:limit, interval: interval, loop: loop
//   , func: () => { 
//       con.end();
//       parentPort.close();
//       console.log(PGNM + "%s ## (%d) End",tcode, threadId); 
//       // process.exit(0) ;
//   }
// } ;

let shttp = () => new sendhttp(param)  ;

shttp() ;

process.on('SIGINT', end_work );
process.on('SIGTERM', end_work );

function end_work() {
  console.log("%s Worker process end : [%d]",PGNM, threadId);
  // process.exit(0);
}