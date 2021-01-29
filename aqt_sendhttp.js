"use strict";

const MAX_RESP_LEN = 8192;
const v_tcode = process.argv[2] ;
if (undefined == v_tcode ) {
  console.info("테스트ID를 지정하세요.") ;
  process.exit(1) ;
}

const moment = require('moment');
const mrdb = require('./db/db_con');

const http = require('http');
moment.prototype.toSqlfmt = function () {
    return this.format('YYYY-MM-DD HH:mm:ss.SSSSSS');
};

const con = mrdb.init() ;
const con2 = mrdb.init() ;
const net = require("net");
const client = new net.Socket();

function dataSend( rdata, qstream ) {
  let resdata = '' ; // JSON.stringify(res.headers) + "\n";
  let stime ; // = moment() ;
  let rtime ; // = moment() ;
  let recvData = [] ;
  client.connect(
    {port:rdata.dstport,
     host:rdata.dstip
    },
    function() {
      console.log("Connected");
      stime = moment() ;
      client.write(rdata.sdata);
    }
  );
  client.on("data", function(data) {
    recvData.push(data)     ;
    client.end() ;
  });
  
  client.on("close", function() {
    console.log("Connection closed");
    
  });
  client.on('end', () =>  {
    rtime = moment();
    if (recvData.length < 1) return ;
    const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;
    let rDatas = Buffer.concat(recvData) ;
    const rsz = rDatas.length ;
    console.log(stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
    // let new_d = Buffer.from(resdata,'binary') ;
    con2.query("UPDATE ttcppacket SET rdata = ?, stime = ?, rtime = ?,  elapsed = ?, rcode = ? , rlen = ? where pkey = ? "
              , [rDatas ,stime.toSqlfmt(), rtime.toSqlfmt(), svctime, rdata.rcode , rsz, rdata.pkey]
              , (err, result) => {
                  if (err) {
                    console.error('update error:',err);
                  };
                  
                  // else console.log("update ok:", result) ;
                }
    );
    qstream.resume()  
  }) ;
  client.on('error', function(err) {
    console.log('Socket Error: ', JSON.stringify(err));
  });
  
}

function dataHandle( rdata, qstream ) {

  const options = { 
    hostname: rdata.dstip , 
    port: rdata.dstport , 
    path: rdata.uri , 
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
    let stime ; // = moment() ;
    // console.log('STATUS: ' + res.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(res.headers));
    let resHs = 'HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage + "\r\n" ;
    for (const [key, value] of Object.entries(res.headers)) {
      resHs += `${key}: ${value}\r\n`;
    };

    // res.setEncoding('utf8');
    let recvData = [] ; 
    res.once('readable', () => {
      stime = moment() ;
    }) ;
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
      const rsz = res.headers['content-length']  || rdata.rlen ;
      let rDatas = Buffer.concat(recvData) ;
      console.log( stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
      // let new_d = Buffer.from(resdata,'binary') ;
      con2.query("UPDATE ttcppacket SET \
                 rdata = ?, stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,rhead = ?, rlen = ? ,cdate = now() where pkey = ?"
                , [rDatas,stime.toSqlfmt(), rtime.toSqlfmt(), svctime, res.statusCode ,resHs,  rsz, rdata.pkey]
                , (err, result) => {
                    if (err) {
                      console.error('update error:',err);
                    } else 
                      console.log("** update ok:", result) ;
                  }
      );
      qstream.resume() ;
    });
  });
  if (rdata.method === 'POST') {
    if (pi > 0) {
      const sdata = rdata.sdata.slice(pi) ;
      console.log(sdata.toString()) ;
      req.write(sdata) ;
    }
  }
  req.on('error', function (e) { console.log('Problem with request: ' + e.message); }) ;
  req.end();
}

console.log("start...",v_tcode ) ;

const qstream =  con.queryStream("SELECT pkey,dstip,dstport,uri,method,sdata, rlen FROM ttcppacket where tcode = ? order by o_stime", [v_tcode]) ;
qstream.on("error", err => {
      console.log(err); //if error
    });
    qstream.on("fields", meta => {
      // console.log(meta); // [ ...]
    });
    qstream.on("data", row => {
      qstream.pause() ;
      //  dataSend(row, qstream);
       dataHandle(row,qstream);
      
    });
    qstream.on("end", () => {
      con.end();
      console.log("read ended");

    }) ;

// setInterval(() => {
//   console.log('check', endflag);
//   if (endflag) {
//     endprog ;
//     process.exit() ;
//   }
// }, 5 * 1000);

function endprog() {
    console.log("program End");
    // child.kill('SIGINT') ;
    con2.end() ;
}

process.on('SIGINT', process.exit );
process.on('SIGTERM', endprog );
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err) ; process.exit } ) ;
process.on('exit', endprog);
