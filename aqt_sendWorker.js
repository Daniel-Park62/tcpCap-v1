"use strict";

const mrdb = require('./db/db_con');
const con = mrdb.init() ;

const PGNM = '[sendWorker]';

const  { parentPort, threadId,  workerData } = require('worker_threads');

console.log("## Start send Data : ",threadId );

const sendhttp = require('./lib/sendHttp') ;

const {tcode, cond, limit } = workerData ;
// const [ tcode, cond, limit ] = process.argv ;
console.log(workerData);
let shttp = () => new sendhttp(tcode, cond, limit, con, () => { 
  con.end();
  parentPort.close();
  console.log("## (%d) End", threadId); 
  process.exit(0) ;
})  ;

shttp() ;

process.on('SIGINT', end_work );
process.on('SIGTERM', end_work );

function end_work() {
  console.log("%s Worker process end : [%d]",PGNM, threadId);
  process.exit(0);
}