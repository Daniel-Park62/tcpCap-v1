"use strict";

const MAX_RESP_LEN = 1024 * 32;
const PGNM = '[aqtExecJob]';

const moment = require('moment');
const mrdb = require('./db/db_con');

const http = require('http');
moment.prototype.toSqlfmt = function () {
    return this.format('YYYY-MM-DD HH:mm:ss.SSSSSS');
};

const con = mrdb.init() ;
// const net = require("net");
// const client = new net.Socket();


console.log(PGNM,"* start Execute Job" ) ;

setInterval( () => {

  con.query("select pkey, jobkind, tcode, tnum,dbskip, exectype,etc,`infile` from texecjob \
                WHERE reqstartdt <= NOW() and resultstat=0 and jobkind in (1,9) order by reqstartdt LIMIT 1" ,
            (err,rows) => {
              if (err) {
                console.log(PGNM,err) ;
                return ;
              } 
              if (rows.length == 0)  return ;
              try {
                con.query("UPDATE texecjob set resultstat = 1, startDt = now() where pkey = ?",[rows[0].pkey]) ;
              } catch(err){
                console.error(err) ;
              }
            
              if (rows[0].jobkind == 1)
                importData(rows[0]);
              else
                sendData(rows[0]);
          
            }
  );

}, 2 * 1000);


function importData(row){
  const cdb = require('./lib/capToDb') ;
  let qstr = "UPDATE texecjob set resultstat = 2, msg = ?, endDt = now() where pkey = " + row.pkey ;
  cdb(row.tcode, row.infile, con, (msg) => { con.query(qstr,[msg]) }  ) ;
}

function sendData(row){
  const sendhttp = require('./lib/sendHttp') ;
  let qstr = "UPDATE texecjob set resultstat = 2, msg = ?, endDt = now() where pkey = " + row.pkey ;
  sendhttp(row.tcode,  row.etc , con , (msg) => { con.query(qstr,[msg]) }  ) ;
  
}

function endprog() {
    console.log(PGNM,"## Exec job program End");
    // child.kill('SIGINT') ;
    con.end() ;
}

process.on('SIGINT', process.exit );
process.on('SIGTERM', endprog );
process.on('uncaughtException', (err) => { console.log(PGNM,'uncaughtException:', err) ; process.exit } ) ;
process.on('exit', endprog);
