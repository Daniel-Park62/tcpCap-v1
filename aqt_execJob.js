"use strict";

const {  Worker,  isMainThread, workerData } = require('worker_threads');

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
                con.query("UPDATE texecjob set resultstat = 1, startDt = now(), endDt = null where pkey = ?",[rows[0].pkey]) ;
              } catch(err){
                console.error(err) ;
              }
            
              if (rows[0].jobkind == 1)
                importData(rows[0]);
              else if (rows[0].tnum > 1)
                sendWorker(rows[0]);
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
  con.query("SELECT lvl FROM TMASTER WHERE CODE = ?",[row.tcode],
  (err,dat) => {
    if (err) {
      console.log(PGNM,err) ;
      con.query("UPDATE texecjob set resultstat = 3, msg = ?, endDt = now() where pkey = ?", [err, row.pkey]) ;
      return ;
    } else if (dat[0].lvl == '0') {
      console.log(PGNM,"Origin ID 는 재전송 불가합니다.") ;
      con.query("UPDATE texecjob set resultstat = 3, msg = 'Origin ID 는 재전송 불가합니다.', endDt = now() where pkey = ?", [row.pkey]) ;
      return ;
    }
    const sendhttp = require('./lib/sendHttp') ;
    let qstr = "UPDATE texecjob set resultstat = 2, msg = ?, endDt = now() where pkey = " + row.pkey ;
    sendhttp(row.tcode,  row.etc , '', con , (msg) => { con.query(qstr,[msg]) }  ) ;
  }) ;
  
}

function sendWorker(row){
  let condi = row.etc > ' ' ? "and ("+ row.etc +")" : "" ;
  const qstr = "SELECT COUNT(*) cnt FROM ttcppacket where tcode = ? " + condi  ;
  const threads = new Set();
  let tcnt = 0, pcnt = 0 ;
  con.query( qstr , [row.tcode] ,
    (err,d) => {
      if (!err) {
        tcnt = d[0].cnt ;
        pcnt = Math.ceil( tcnt / row.tnum ) ;
        
      } else 
        console.log(PGNM,err) ;
    }
  );
  
  setTimeout(  () => {
    console.log(PGNM, tcnt, pcnt);
    let msgs = '';
    for (let i = 0 ;  i < tcnt ;  i += pcnt ){
      let i2 = pcnt ;
      if ( tcnt < i+pcnt) i2 = ( tcnt - i ) ;

      const wdata = { workerData: {tcode:row.tcode, cond: row.etc, limit: `${i},${i2}`  } };
      // const wdata =  [row.tcode, row.etc,  `${i},${pcnt}`  ];
      console.log(PGNM, wdata) ;
      msgs  += wdata.workerData.limit," : ";
      const wkthread = new Worker(__dirname + '/aqt_sendWorker.js' ,  wdata ) 
      .on('exit', () => {
        threads.delete(wkthread);
       
        console.log(PGNM,`Thread exiting, ${threads.size} running...`);
        if (threads.size == 0) {
          console.log(PGNM, 'thread all ended !!')
          const qstr = "UPDATE texecjob set resultstat = 2, msg = ?, endDt = now() where pkey = " + row.pkey ;
          con.query(qstr,[msgs]) ;
        }
      });
      threads.add(wkthread);
      // wkthread.postMessage(wdata) ;

    }
  },1000) ;

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
