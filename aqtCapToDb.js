"use strict";

const MAX_RESP_LEN = 8192;
const dstv = process.argv[2];
const CN_TCODE = process.argv[3];
if (undefined == dstv) {
    console.info("대상 파일(또는 host)을 지정하세요.");
    process.exit(1);
}
if (undefined == CN_TCODE) {
    console.info("저장될 테스트ID를 지정하세요.");
    console.info("aqtCapTodb 호스트(파일) 테스트id");
    process.exit(1);
}
console.info( process.argv[2], CN_TCODE );
const mysql_dbc = require('./db/db_con');
const con = mysql_dbc.init();
const { spawn } = require('child_process');

const util = require('util');
const pcapp = require('./lib/pcap-parser');

const moment = require('moment');
const decoders = require('./lib/Decoders')
const PROTOCOL = decoders.PROTOCOL;
let myMap = new Map();
const fs = require('fs');
let dstobj ;
try {
    fs.statSync(dstv);
    dstobj = dstv;
} catch (err) {
    const child = spawn("tcpdump -s0 -n -w - " ,['tcp and host',  dstv ], { shell: true });
    dstobj = child.stdout ;
}

const parser = pcapp.parse(dstobj);

parser.on('packet', function (packet) {

    let ret = decoders.Ethernet(packet.data);
    let ptime = moment.unix(packet.header.timestampSeconds ).format('YYYY-MM-DD HH:mm:ss')  + '.' + packet.header.timestampMicroseconds ;
    let buffer = packet.data;
    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
        // console.log('Decoding IPv4 ...');

        ret = decoders.IPV4(buffer, ret.offset);
        //   console.log(ret) ;
        if (ret.info.totallen <= 40) return;
        // console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr, 'tottal len ', ret.info.totallen);
        const srcip = ret.info.srcaddr;
        const dstip = ret.info.dstaddr;

        if (ret.info.protocol === PROTOCOL.IP.TCP) {
            let datalen = ret.info.totallen - ret.hdrlen;

            // console.log('Decoding TCP ...');

            ret = decoders.TCP(buffer, ret.offset);
            // console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
            datalen -= ret.hdrlen;
            if (datalen <= 0)  return ;
            // console.log('seqno ', ret.info.seqno, 'ackno ', ret.info.ackno, 'datalen ', datalen, ' next ', ret.info.seqno + datalen);
            // console.log(ret) ;
            // console.log(buffer.toString('binary', ret.offset, ret.offset + datalen));
            // console.log(buffer.slice(ret.offset, ret.offset + 200).toString());
            let ky = util.format('%s:%d:%d', srcip, ret.info.srcport, ret.info.ackno) ;
            if (/^(GET|POST|DELETE|PUT)/.test(buffer.slice(ret.offset, ret.offset + 10).toString())) {
                let sdata = buffer.slice(ret.offset, ret.offset + datalen);
                let mdata = /^(GET|POST|DELETE|PUT)\s+(\S+)\s/s.exec(sdata.toString());
                ky = util.format('%s:%d:%d', dstip, ret.info.dstport, ret.info.seqno + datalen) ;
                let datas = {
                    tcode: CN_TCODE,
                    method: mdata[1],
                    uri: mdata[2],
                    o_stime: ptime,
                    stime: ptime,
                    sdata: sdata,
                    slen: datalen,
                    srcip: srcip,
                    dstip: dstip,
                    srcport: ret.info.srcport,
                    dstport: ret.info.dstport,
                    seqno: ret.info.seqno,
                    ackno: ret.info.ackno,
                    rhead:'',
                };
                myMap.set(ky, datas) ;
            } else if(myMap.has(ky)) {
                
                let datas = myMap.get(ky) ;
                datas.rtime = ptime ;
                let pi = buffer.indexOf("\r\n\r\n");
                if  (pi == -1) {
                    pi = ret.offset  ;
                };
                let res = buffer.slice(ret.offset, pi).toString() 
                if (res.match(/Content-Type:\s*image/)) {
                    myMap.delete(ky) ;
                    // console.log(res) ;
                    return ;
                };
                if ( /^HTTP\/.+/s.test(res)) datas.rhead = res ;
                
                let rcode = /^HTTP.+?\s(\d+?)\s(?:.*Content-Length:\s?(\d+))?\s/s.exec(res) ;
                if ( rcode ) {
                    datas.rcode = Number(rcode[1]) ;
                    datas.rlen = Number(rcode[2]) || datalen ;
                    datas.rdata = buffer.slice(pi);
                    // datas.rdata = buffer.slice(ret.offset, ret.offset + datalen);
                    // console.log(datas );
                    // console.log(datas.rdata.toString() );
                } else {
                    if (datas.rdata) 
                        datas.rdata = Buffer.concat( [ datas.rdata, buffer.slice(ret.offset, ret.offset + datalen) ] ) ;
                    else
                        datas.rdata = buffer.slice(ret.offset, ret.offset + datalen);
                };
                
                if (datas.rlen > 0 && ( datas.rdata.length >= (  MAX_RESP_LEN >= datas.rlen ? MAX_RESP_LEN : datas.rlen)) ) {
                    con.query("INSERT INTO TTCPPACKET \
                            (TCODE, O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,RHEAD,slen,rlen,SDATA,RDATA) \
                            values \
                            (?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?) ;",
                            [CN_TCODE, datas.o_stime, datas.stime ,datas.rtime,datas.srcip,datas.srcport,datas.dstip,datas.dstport, 1, 
                                datas.method,datas.uri,datas.seqno,datas.ackno,datas.rcode, datas.rhead, datas.slen,datas.rlen,datas.sdata,datas.rdata],
                        (err, dt) => {
                        if (err) 
                            console.error(err);
                        else
                            console.log("** insert ok ", datas.uri) ;

                        }
                    ) ;
                    myMap.delete(ky) ;
                } else {
                    myMap.set(ky, datas) ;
                }
            }

        } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
            console.log('Decoding UDP ...');

            ret = decoders.UDP(buffer, ret.offset);
            console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);

            console.log(buffer.toString('binary', ret.offset, ret.offset + ret.info.length));
        } else
            console.log('Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
    } else
        console.log('Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);


});

parser.on('end', process.exit );
/* 

const fs = require('fs');
const rr = fs.createReadStream(dstv);
rr.on('readable', () => {
  console.log(`readable: ${rr.read()}`);
});
rr.on('end', () => {
  console.log('end');
});


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

*/

function endprog() {

    con.query("UPDATE TTCPPACKET SET CMPID = PKEY WHERE TCODE = ? and CMPID = 0 ",   [CN_TCODE],
        (err, dt) => {
            if (err)
                console.error(err);
            else
                console.log("## UPDATE ok ", datas.uri);

            con.end();

        }
    );
    
    console.log("*** program End ***");

    // child.kill('SIGINT') ;
    
    // process.exit();
}
process.on('SIGINT', process.exit);
process.on('SIGTERM', endprog);
process.on('uncaughtException', (err) => { console.log('uncaughtException:', err); process.exit });
process.on('exit', endprog);
// hid.close() ;

