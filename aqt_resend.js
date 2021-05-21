"use strict";
const PGNM = '[Resend]';
const MAX_RESP_LEN = 1024 * 32;
const Dsec = /^\d+$/.test(process.argv[2])  ? process.argv[2] * 1 : 5 ;
const moment = require('moment');
const mrdb = require('./db/db_con');

const http = require('http');
moment.prototype.toSqlfmt = function (ms) {
    return this.format('YYYY-MM-DD HH:mm:ss.' + ms);
};

const con = mrdb.init() ;
// const net = require("net");
// const client = new net.Socket();

async function dataHandle( rdata, qstream ) {
  let uri = /^(GET|POST|DELETE|PUT|PATCH)\s+(\S+)\s/s.exec(rdata.sdata.toString())[2];
  if ( uri.indexOf('%') == -1) uri = encodeURI(uri) ;

  const options = { 
    hostname: rdata.dstip , 
    port: rdata.dstport , 
    path: uri , 
    method: rdata.method ,
    timeout: 5000,
    headers: {
      // connection: "keep-alive",
    },
  };
  const pi = rdata.sdata.indexOf("\r\n\r\n");
  const shead = (pi > 0) ? rdata.sdata.slice(0,pi).toString() : rdata.sdata.toString() ;
  const shead2 = shead.split('\r\n') ;
  let new_shead = shead2[0] + '\r\n';
  // console.log(shead2) ;
  shead2.forEach(v => {
    const kv = v.split(':') ;
    let val = kv.slice(1).join(':').trim() ;
    // if (/(Content-Type|Referer|upgrade-Insecure-Requests|Accept|Cookie)/.test(kv[0])) {
    if (! /^(GET|POST|DELETE|PUT|PATCH|Host)/.test(kv[0])) {
        if (kv[0].length > 0) {
          options.headers[kv[0]] = val  ;
          new_shead += kv[0] + ': ' + val + '\r\n';
        }
    }
  });
  let stime  = moment() ;  
  let stimem = Math.ceil(process.hrtime()[1] / 1000) ;
  // console.log(options.headers) ;
  const req = http.request(options, function (res) {
    // stime  = moment() ;
    // console.log('STATUS: ' + res.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(res.headers));
    let resHs = 'HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage + "\r\n" ;
    for (const [key, value] of Object.entries(res.headers)) {
      resHs += `${key}: ${value}\r\n`;
      if (/set-cookie/i.test(key)) {
        saveCookie( rdata, `${value}` ) ;
      }

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
      // if (recvData.length < 1)  {
      //   qstream.resume() ;
      //   return ;
      // }
      const rtime = moment();
      const rtimem = Math.ceil(process.hrtime()[1] / 1000) ;
      const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;
      // recvData[0] = bufTrim(recvData[0]) ;
      let rDatas = Buffer.concat(recvData) ;
      const rsz = res.headers['content-length']  || rDatas.length ;
      
      // console.log( stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
      // let new_d = Buffer.from(resdata,'binary') ;
      con.query("UPDATE ttcppacket SET \
                 rdata = ?, sdata=?, stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,rhead = ?, rlen = ? ,cdate = now() where pkey = ? " 
                , [rDatas,Buffer.from(new_shead), stime.toSqlfmt(stimem), rtime.toSqlfmt(rtimem), svctime, res.statusCode ,resHs,  rsz, rdata.pkey]
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
  if ( pi > 0 && /POST|PUT|DELETE|PATCH/.test(rdata.method)  ) {
      const sdata = rdata.sdata.slice(pi+4) ;
      // console.log(sdata.toString()) ;
      req.write(sdata) ;
      new_shead += '\r\n' + sdata.toString() ;
  }
  req.on('error', function (e) { 
    console.log(PGNM,'Problem with request: ', e.message, e.errno);
    const rtime = moment();
    const rtimem = Math.ceil(process.hrtime()[1] / 1000) ;

    const svctime = moment.duration(rtime.diff(stime)) / 1000.0 ;

    con.query("UPDATE ttcppacket SET \
                  sdata = ? , stime = ?, rtime = ?,  elapsed = ?, rcode = ?,  rhead = ? ,cdate = now() where pkey = ?"
                , [Buffer.from(new_shead),stime.toSqlfmt(stimem), rtime.toSqlfmt(rtimem), svctime, 999, e.message, rdata.pkey]
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

console.log("%s * start Resend check (%d 초 단위)", PGNM,  Dsec) ;
const sendhttp = require('./lib/sendHttp') ;
setInterval(() => {

    const qstream = con.queryStream("SELECT pkey FROM trequest order by reqDt  " );
    qstream.on("error", err => {
        console.log(PGNM,err); //if error
    });
    qstream.on("fields", meta => {
        // console.log(meta); // [ ...]
    });
    qstream.on("data", row => {
        qstream.pause();
        
        con.query("SELECT t.pkey,o_stime, if( ifnull(m.thost2,IFNULL(c.thost,''))>'',ifnull(m.thost2,c.thost) ,dstip) dstip, if(ifnull(m.tport2,IFNULL(c.tport,0))>0, ifnull(m.tport2,c.tport), dstport) dstport,uri,method,sdata, rlen " + 
          "FROM ttcppacket t join tmaster c on (t.tcode = c.code ) left join thostmap m on (t.tcode = m.tcode and t.dstip = m.thost and t.dstport = m.tport) " +
          "where t.pkey = ? ", [row.pkey]
            , async (err, row2) => {
                if (err) {
                    console.error(PGNM,"select error :", err);
                    qstream.resume();
                } else {
                    console.log("%s ID (%d) Re-send", PGNM, row.pkey);
                    dataHandle(row2[0], qstream );
                    con.query("DELETE FROM trequest where pkey = ?", [row.pkey]) ;
                }
            }
        );
    });
    // qstream.on("end", () => {
    //     console.log(PGNM,"read ended");
    // });
}, Dsec * 1000);

// setInterval(() => {
//   console.log('check', endflag);
//   if (endflag) {
//     endprog ;
//     process.exit() ;
//   }
// }, 5 * 1000);

function bufTrim(buf) {
  // let pi = buf.length > 100 ? 100 : buf.length;
  if (buf == undefined) return Buffer.from('');
  let str = buf.toString();
  str = str.replace(/^\s+/, '');
  // str = str.replace(/^[0-9a-fA-F]+\s*\r\n\r\n\s*/, '');
  // return Buffer.concat([Buffer.from(str), buf.slice(pi)]);
  return Buffer.from(str) ;
}

function endprog() {
    console.log(PGNM,"program End");
    // child.kill('SIGINT') ;
    con.end() ;
}

const ckMap = new Map();  // cookie 저장
const parseCookies = ( cookie = '' ) => {
  // console.log("cookie : ",cookie);
  return cookie
      .split(';')
      .map( v => v.split('=') )
      .map( ([k, ...vs]) => [k, vs.join('=')] )
      .reduce( (acc, [k,v]) => {
          acc[k.trim()] = v ; // decodeURIComponent(v);
          return acc;
      }, {});
}

function saveCookie(rdata, cook) {
  const ckData = parseCookies( cook ) ;
  const path = ckData.Path || '/' ;
  let sv_ckData = ckMap.get(rdata.dstip+rdata.dstport) || {} ;
  let xdata = sv_ckData[path] || {} ;
  for (const k in ckData) {
    if (/Path|HttpOnly|Secure/.test(k))  continue ;
    xdata[k] = ckData[k] ;
  }

  sv_ckData[path] = xdata ;
  ckMap.set(rdata.dstip+rdata.dstport, sv_ckData) ;
  // console.log(sv_ckData) ;

}

process.on('SIGINT', process.exit );
process.on('SIGTERM', endprog );
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err) ; process.exit } ) ;
process.on('exit', endprog);
