"use strict";

const dstv = process.argv[2] ;
if (undefined == dstv ) {
  console.info("대상 host를 지정하세요.") ;
  process.exit(1) ;
}
const moment = require('moment');
const mysql_dbc = require('./db/db_con');
const con = mysql_dbc.init() ;
const { spawn } = require('child_process');

con.query("SELECT * FROM tconfig LIMIT 1", (err,rows) =>
        {
          if (err) {
            console.error(err) ;
          } else {
            console.log("rows:", rows[0].id, rows[0].pass1); //[ {val: 1}, meta: ... ]
          }
  }) ;
// const fs = require('fs');
// const rr = fs.createReadStream('test01.pcap');
// rr.on('readable', () => {
//   console.log(`readable: ${rr.read()}`);
// });
// rr.on('end', () => {
//   console.log('end');
// });

// process.stdin.resume();
// process.stdin.on()'readable', () => dataHandle(process.stdin) ) ;
// process.stdin.on('error', function(code) {
//     console.log('error: ' + code);
// });
// process.stdin.on('end', console.log('end !!'));

const child = spawn('perl ', ['aqtRealrcv.pl ', dstv ], { shell: true });

// const child = spawn('ls ', ['-l'], { shell: true } ).on('error',err => console.error('onerror:',err) );
child.on('exit', function(code) {
    console.log('exit: ' + code);
});
child.stdout.on('close', function(code) {
    console.log('close: ' + code);
});
child.stdout.on('end', function(code) {
    console.log('end: ' + code);
});
child.stdout.on('error', function(code) {
    console.log('sto error: ' + code);
});
child.on('error', function(code) {
    console.log('error: ' + code);
});

// child.stdout.on('data', function(data) {
//     let szn = Number(data.slice(0,8)) ;
//     let srcip = data.toString().substr(8,30) ;
//     let srcport = data.readUInt16BE(38) ;
//     let rdata = data.slice(80).toString() ;
//     console.log('data :', szn, srcip, srcport, rdata ) ;
// });
const myre = /^(\w+)\s([\S]+?)\s/ ;
const myre2 = /^.+?\s(\d+?)\s/ ;

function dataHandle(stream ) {
  let sz,svctime ;
  while ( sz =  stream.read(8)  ) {

    let szn = Number(sz) ;
    console.log("size:",  szn);
    if (szn > 0){

      let data ;
      data = stream.read(szn)  ;
      continue;
      console.log(data.toString()) ;
      let srcip = data.slice(0,30).toString() ;
      let srcport = data.readUInt16BE(30) ;
      let dstip = data.slice(32,62).toString() ;
      let dstport = data.readUInt16BE(62) ;
      let stime = data.slice(64,94).toString() ;
      let seqno = data.readUInt32BE(94);
      let ackno = data.readUInt32BE(98);
      let sdata = data.slice(102) ;
      let ix = sdata.indexOf(Buffer.from('@@')) ;
      let rdata = '';
      let rtime = stime.slice(1) ;
      if (ix >= 0) {
        rtime = sdata.slice(ix+2,ix+2+30).toString() ;
        rdata = sdata.slice(ix+32) ;
        sdata = sdata.slice(0,ix) ;
      }
      let muri = myre.exec(sdata.toString()) ;
      let rcode = myre2.exec(rdata.toString())[1] ;
      console.log('[%s ~ %s] %s:%d %s:%d', stime ,rtime, srcip, srcport, dstip, dstport ) ;
      console.log('sdata :', sdata.toString() ) ;
      console.log('rdata :', rdata.toString() ) ;

      con.query("INSERT INTO TTCPPACKET \
                (TCODE,O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,slen,rlen,SDATA,RDATA, cdate) values \
                ('TH02',?,?,?,?,?,?,?,'1',?,?,?,?,?,?,?,?, ?,now() )" ,
                [ stime,stime, rtime, srcip,srcport,dstip,dstport,
                  muri[1],muri[2], seqno, ackno,rcode,Buffer.byteLength(sdata),Buffer.byteLength(rdata),sdata, rdata],
                  (err, dt) => {
                    if (err) console.error(err);
                  }

      );
    }
  }
  console.log( 'while end ');
}

child.stdout.on('readable', () => dataHandle(child.stdout));
// child.stdout.on('data', data => console.log('data:',data) ) ;
// setInterval(() => { console.log(child.stdout.readableFlowing, child.stdout.isPaused() , child.stdout.destroyed, child.stdout.readable) }, 1000) ;

function endprog() {
  console.log("program End");
  // child.kill('SIGINT') ;
  con.end();
  // process.exit();
}

process.on('SIGINT', process.exit);
process.on('SIGTERM', endprog);
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err); process.exit });
process.on('exit', endprog);
// hid.close() ;
