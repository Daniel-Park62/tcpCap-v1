"use strict";

const MAX_RESP_LEN = 1024 * 32;
const PGNM = '[sendHttp]';

const moment = require('moment');

const http = require('http');
moment.prototype.toSqlfmt = function () {
  return this.format('YYYY-MM-DD HH:mm:ss.SSSSSS');
};

let con = null;

module.exports = async function (p_tcode, p_cond, p_conn, p_func ) {
  con = p_conn ;

  let tcnt = 0;
  let  cnt = 0;
  const qstr = "SELECT COUNT(*) cnt FROM ttcppacket where tcode = ? " + (p_cond ? p_cond : "") ;
  
  await con.query( qstr , [p_tcode] ,
    (err,row) => {
      if (!err) {
        tcnt = row[0].cnt ;
        console.log("%s Start 테스트id(%s) (%s) data건수 (%d)" ,PGNM,  p_tcode,  p_cond,  tcnt);
      } else 
        console.log(PGNM,err) ;
    }
  );

  const qstream = con.queryStream("SELECT pkey,o_stime, dstip,dstport,uri,method,sdata, rlen FROM ttcppacket where tcode = ? "
    + (p_cond ? p_cond : "") + " order by o_stime  ", [p_tcode]);
  qstream.on("error", err => {
    console.log(PGNM,err); //if error
  });
  qstream.on("fields", meta => {
    // console.log(PGNM,meta); // [ ...]
  });
  qstream.on("data", row => {
    qstream.pause();
    //  dataSend(row, qstream);
    dataHandle(row, qstream, () => {cnt++} );
  });

  qstream.on("end", () => {
    console.log(PGNM,"*** read ended ***");
    
    let ival = setInterval( () => {
      console.log(PGNM,"@@ end check @@", tcnt, cnt);
      if (cnt >= tcnt) { 
        con.query('call sp_summary(?)',[p_tcode]) ;
        console.log(PGNM,"** end check **"); 
        clearInterval(ival); 
        p_func(cnt + " 건 송신"); 
      } 
    }, 2000);
  });
}

function dataHandle(rdata, qstream, pfunc) {
  let stime = moment();
  let uri = /^(GET|POST|DELETE|PUT)\s+(\S+)\s/s.exec(rdata.sdata.toString())[2];
  const options = {
    hostname: rdata.dstip,
    port: rdata.dstport,
    path: uri,
    method: rdata.method,
    headers: {
      connection: "keep-alive",
    },
  };
  const pi = rdata.sdata.indexOf("\r\n\r\n");
  const shead = (pi > 0) ? rdata.sdata.slice(0, pi).toString() : rdata.sdata.toString();
  const shead2 = shead.split('\r\n');
  // console.log(PGNM,shead2) ;
  shead2.forEach(v => {
    const kv = v.split(':');
    if (/(Content-Type|Referer|upgrade-Insecure-Requests|Accept|Cookie)/.test(kv[0])) {
      options.headers[kv[0]] = kv.slice(1).join(':');
    }
  });
  // console.log(PGNM,JSON.stringify(options)) ;
  const req = http.request(options, function (res) {
    stime = moment();
    // console.log(PGNM,'STATUS: ' + res.statusCode);
    // console.log(PGNM,'HEADERS: ' + JSON.stringify(res.headers));
    let resHs = 'HTTP/' + res.httpVersion + ' ' + res.statusCode + ' ' + res.statusMessage + "\r\n";
    for (const [key, value] of Object.entries(res.headers)) {
      resHs += `${key}: ${value}\r\n`;
    };

    // res.setEncoding('utf8');
    let recvData = [];
    // res.once('readable', () => {
    //   stime = moment() ;
    // }) ;
    res.on('data', function (chunk) {
      recvData.push(chunk);
    });
    res.on('end', () => {
      pfunc() ;
      if (recvData.length < 1) {
        qstream.resume();
        return;
      }
      const rtime = moment();
      const svctime = moment.duration(rtime.diff(stime)) / 1000.0;
      recvData[0] = bufTrim(recvData[0]);
      let rDatas = Buffer.concat(recvData);
      const rsz = res.headers['content-length'] || rDatas.length;

      // console.log(PGNM, stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 'id=',rdata.pkey, 'rcv len=', rsz );
      // let new_d = Buffer.from(resdata,'binary') ;
      con.query("UPDATE ttcppacket SET \
                     rdata = ?, stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,rhead = ?, rlen = ? ,cdate = now() where pkey = ? "
        , [rDatas, stime.toSqlfmt(), rtime.toSqlfmt(), svctime, res.statusCode, resHs, rsz, rdata.pkey]
        , (err, result) => {
          if (err)
            console.error(PGNM,'update error:', rdata.pkey, err);
          // else
          //   console.log(PGNM,"** update ok:", rdata.pkey, uri);
          qstream.resume();
        }
      );

    });
  });
  if (rdata.method === 'POST') {
    if (pi > 0) {
      const sdata = rdata.sdata.slice(pi);
      // console.log(PGNM,sdata.toString()) ;
      req.write(sdata);
    }
  }
  req.on('error', function (e) {
    pfunc() ;
    console.log(PGNM,'Problem with request: ', e.message, e.errno );
    const rtime = moment();
    const svctime = moment.duration(rtime.diff(stime)) / 1000.0;

    con.query("UPDATE ttcppacket SET \
                      stime = ?, rtime = ?,  elapsed = ?, rcode = ? ,cdate = now() where pkey = ?"
      , [stime.toSqlfmt(), rtime.toSqlfmt(), svctime, 999, rdata.pkey]
      , (err, result) => {
        if (err)
          console.error('update error:', err);
        // else
        //   console.log(PGNM,"** err update ok:", rdata.pkey, uri);
        qstream.resume();
      }
    );

  });
  req.end();
}

function bufTrim(buf) {
  // let pi = buf.length > 100 ? 100 : buf.length;
  let str = buf.toString();
  str = str.replace(/^\s+/, '');
  // str = str.replace(/^[0-9a-fA-F]+\s*\r\n\r\n\s*/, '');
  // return Buffer.concat([Buffer.from(str), buf.slice(pi)]);
  return Buffer.from(str);
}
