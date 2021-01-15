"use strict";

const v_tcode = process.argv[2] ;
if (undefined == v_tcode ) {
  console.info("테스트ID를 지정하세요.") ;
  process.exit(1) ;
}

const moment = require('moment');
const mrdb = require('./db/db_con');

const http = require('http');
moment.prototype.toSqlfmt = function () {
    return this.format('YYYY-MM-DD HH:mm:ss');
};

const con = mrdb.init() ;

const con2 = mrdb.init() ;

function dataHandle( rdata ) {

  const options = { hostname: rdata.dstip , port: rdata.dstport , path: rdata.uri , method: rdata.method };

  const req = http.request(options, function (res) {
    let resdata = '' ; // JSON.stringify(res.headers) + "\n";
    let stime ; // = moment() ;
    // console.log('STATUS: ' + res.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(res.headers));
    // res.setEncoding('utf8');
    res.once('readable', () => {
      stime = moment() ;
    })
    res.on('data', function (chunk) {
      resdata += chunk ;
    });
    res.on('end',  function () {
      const rtime = moment();
      const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;
      const rsz = res.headers['content-length'] ;
      console.log(stime.format('m:s.SSS'), rtime.format('m:s.SSS'), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
      // let new_d = Buffer.from(resdata,'binary') ;
      con2.query("UPDATE ttcppacket SET rdata = ?, stime = ?, rtime = ?, svctime = ?, rcode = ? , rlen = ? where pkey = ?"
                , [resdata,stime.toSqlfmt(), rtime.toSqlfmt(), svctime, res.statusCode , rsz, rdata.pkey]
                , (err, result) => {
                    if (err) {
                      console.error('update error:',err);
                    }
                    // else console.log("update ok:", result) ;
                  }
      );
    });
  });

  req.on('error', function (e) { console.log('Problem with request: ' + e.message); }) ;
  req.end();
}


console.log("start...",v_tcode ) ;

  con.queryStream("SELECT * FROM ttcppacket where tcode = ?", [v_tcode])
    .on("error", err => {
      console.log(err); //if error
    })
    .on("fields", meta => {
      // console.log(meta); // [ ...]
    })
    .on("data", row => {
       dataHandle(row);
    })
    .on("end", () => {
      con.end();
      console.log("read ended");
    }) ;


function endprog() {
    console.log("program End");
    // child.kill('SIGINT') ;
    con2.end() ;
}

process.on('SIGINT', process.exit );
process.on('SIGTERM', endprog );
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err) ; process.exit } ) ;
process.on('exit', endprog);
