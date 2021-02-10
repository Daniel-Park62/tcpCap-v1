"use strict";

const MAX_RESP_LEN = 1024 * 32;

const moment = require('moment');
const mrdb = require('./db/db_con');

const http = require('http');
moment.prototype.toSqlfmt = function () {
    return this.format('YYYY-MM-DD HH:mm:ss.SSSSSS');
};

const con = mrdb.init() ;
// const net = require("net");
// const client = new net.Socket();

function dataHandle( rdata, qstream ) {
    
  let uri = /^(GET|POST|DELETE|PUT)\s+(\S+)\s/s.exec(rdata.sdata.toString())[2];
  const options = { 
    hostname: rdata.dstip , 
    port: rdata.dstport , 
    path: uri , 
    method: rdata.method ,
    headers: {
      connection: "keep-alive",
    },
  };
  const pi = rdata.sdata.indexOf("\r\n\r\n");
  const shead = (pi > 0) ? rdata.sdata.slice(0,pi).toString() : rdata.sdata.toString() ;
  const shead2 = shead.split('\r\n') ;
  // console.log(shead2) ;
  shead2.forEach(v => {
    const kv = v.split(':') ;
    if (/(Content-Type|Referer|upgrade-Insecure-Requests|Accept|Cookie)/.test(kv[0])) {
      options.headers[kv[0]] = kv.slice(1).join(':') ;
    }
  });
  // console.log(JSON.stringify(options)) ;
  const req = http.request(options, function (res) {
    let stime  = moment() ;
    // console.log('STATUS: ' + res.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(res.headers));
    let resHs = 'HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage + "\r\n" ;
    for (const [key, value] of Object.entries(res.headers)) {
      resHs += `${key}: ${value}\r\n`;
    };

    // res.setEncoding('utf8');
    let recvData = [] ; 
    // res.once('readable', () => {
    //   stime = moment() ;
    // }) ;
    res.on('data', function (chunk) {
      recvData.push(chunk) ;
    });
    res.on('end',  function () {
      if (recvData.length < 1)  {
        return ;
        qstream.resume() ;
      }
      const rtime = moment();
      const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;
      recvData[0] = bufTrim(recvData[0]) ;
      let rDatas = Buffer.concat(recvData) ;
      const rsz = res.headers['content-length']  || rDatas.length ;
      
      // console.log( stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
      // let new_d = Buffer.from(resdata,'binary') ;
      con.query("UPDATE ttcppacket SET \
                 rdata = ?, stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,rhead = ?, rlen = ? ,cdate = now() where pkey = ? " 
                , [rDatas,stime.toSqlfmt(), rtime.toSqlfmt(), svctime, res.statusCode ,resHs,  rsz, rdata.pkey]
                , (err, result) => {
                    if (err) 
                      console.error('update error:',rdata.pkey, err);
                    else 
                      console.log("** update ok:", rdata.pkey, uri) ;
                    qstream.resume() ;
                  }
      );
      
    });
  });
  if (rdata.method === 'POST') {
    if (pi > 0) {
      const sdata = rdata.sdata.slice(pi) ;
      // console.log(sdata.toString()) ;
      req.write(sdata) ;
    }
  }
  req.on('error', function (e) { 
    console.log('Problem with request: ', e, options ); 
    const rtime = moment();
    const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;

    con.query("UPDATE ttcppacket SET \
                  stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,cdate = now() where pkey = ?"
                , [stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 999, rdata.pkey]
                , (err, result) => {
                    if (err) 
                      console.error('update error:',err);
                    else 
                      console.log("** err update ok:", rdata.pkey, uri ) ;
                    qstream.resume() ;
                  }
      );
    
  }) ;
  req.end();
}

console.log("* start Resend check" ) ;

setInterval(() => {

    const qstream = con.queryStream("SELECT pkey FROM trequest order by reqDt  " );
    qstream.on("error", err => {
        console.log(err); //if error
    });
    qstream.on("fields", meta => {
        // console.log(meta); // [ ...]
    });
    qstream.on("data", row => {
        qstream.pause();
        con.query("SELECT pkey,dstip,dstport,uri,method,sdata, rlen FROM ttcppacket where pkey = ? ", [row.pkey]
            , (err, row2) => {
                if (err) {
                    console.error("select error :", err);
                    qstream.resume();
                } else {
                    dataHandle(row2[0], qstream);
                    con.query("DELETE FROM trequest where pkey = ?", [row.pkey]) ;
                }
            }
        );
    });
    qstream.on("end", () => {
        console.log("read ended");
    });
}, 5 * 1000);

// setInterval(() => {
//   console.log('check', endflag);
//   if (endflag) {
//     endprog ;
//     process.exit() ;
//   }
// }, 5 * 1000);

function bufTrim(buf) {
  // let pi = buf.length > 100 ? 100 : buf.length;
  let str = buf.toString();
  str = str.replace(/^\s+/, '');
  // str = str.replace(/^[0-9a-fA-F]+\s*\r\n\r\n\s*/, '');
  // return Buffer.concat([Buffer.from(str), buf.slice(pi)]);
  return Buffer.from(str) ;
}

function endprog() {
    console.log("program End");
    // child.kill('SIGINT') ;
    con.end() ;
}

process.on('SIGINT', process.exit );
process.on('SIGTERM', endprog );
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err) ; process.exit } ) ;
process.on('exit', endprog);
