"use strict";

const MAX_RESP_LEN = 1024 * 32;
const PGNM = '[capToDb]';

let myMap = new Map();
let con = null ;
process.on('SIGTERM', endprog);
process.on('warning', (warning) => {
    console.warn(warning.name);    // Print the warning name
    console.warn(warning.message); // Print the warning message
    console.warn(warning.stack);   // Print the stack trace
});
let icnt = 0 ;

module.exports = function (p_tcode, dstv, p_con, p_func) {
    let cn_tcode = p_tcode;
    con = p_con ;
    const { spawn } = require('child_process');

    const util = require('util');
    const pcapp = require('./pcap-parser');

    const moment = require('moment');
    const decoders = require('./Decoders')
    const PROTOCOL = decoders.PROTOCOL;
    const fs = require('fs');
    let dstobj;
    console.log("%s Start 테스트id(%s) 입력파일(%s)", PGNM,cn_tcode, dstv);

    try {
        fs.statSync(dstv);
        dstobj = dstv;
    } catch (err) {
        console.log(PGNM,err);
        const child = spawn("tcpdump -s0 -n -w - ", ['tcp and host', dstv], { shell: true });
        dstobj = child.stdout;
    }

    const parser = pcapp.parse(dstobj);

    parser.on('packet', function (packet) {

        let ret = decoders.Ethernet(packet.data);
        let ptime = moment.unix(packet.header.timestampSeconds).format('YYYY-MM-DD HH:mm:ss') + '.' + packet.header.timestampMicroseconds;
        let buffer = packet.data;
        if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
            // console.log(PGNM,'Decoding IPv4 ...');

            ret = decoders.IPV4(buffer, ret.offset);
            //   console.log(PGNM,ret) ;
            if (ret.info.totallen <= 40) return;
            // console.log(PGNM,'from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr, 'tottal len ', ret.info.totallen);
            const srcip = ret.info.srcaddr;
            const dstip = ret.info.dstaddr;

            if (ret.info.protocol === PROTOCOL.IP.TCP) {
                let datalen = ret.info.totallen - ret.hdrlen;

                // console.log(PGNM,'Decoding TCP ...');

                ret = decoders.TCP(buffer, ret.offset);
                // console.log(PGNM,' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
                datalen -= ret.hdrlen;
                if (datalen <= 0) return;
                // console.log(PGNM,'seqno ', ret.info.seqno, 'ackno ', ret.info.ackno, 'datalen ', datalen, ' next ', ret.info.seqno + datalen);
                // console.log(PGNM,ret) ;
                // console.log(PGNM,buffer.toString('binary', ret.offset, ret.offset + datalen));
                // console.log(PGNM,buffer.slice(ret.offset, ret.offset + 200).toString());
                let ky = util.format('%s:%d:%d', srcip, ret.info.srcport, ret.info.ackno);
                if (/^(GET|POST|DELETE|PUT)\s/.test(buffer.slice(ret.offset, ret.offset + 10).toString())) {
                    // let sdata = buffer.slice(ret.offset, ret.offset + datalen);
                    let sdata = buffer.slice(ret.offset);
                    let mdata = /^(GET|POST|DELETE|PUT)\s+(\S+?)[?\s]/s.exec(sdata.toString());
                    if (mdata == undefined) {
                        console.log(PGNM,sdata.toString());
                        return;
                    }
                    ky = util.format('%s:%d:%d', dstip, ret.info.dstport, ret.info.seqno + datalen);
                    let datas = {
                        tcode: cn_tcode,
                        method: mdata[1],
                        uri: mdata[2],
                        o_stime: ptime,
                        stime: ptime,
                        rtime: ptime,
                        sdata: sdata,
                        slen: datalen,
                        rlen: 0,
                        srcip: srcip,
                        dstip: dstip,
                        srcport: ret.info.srcport,
                        dstport: ret.info.dstport,
                        seqno: ret.info.seqno,
                        ackno: ret.info.ackno,
                        rhead: '',
                        rcode: 0,
                    };
                    if (!datas.uri.match('\.css$'))
                        myMap.set(ky, datas);
                } else if (myMap.has(ky)) {

                    let datas = myMap.get(ky);
                    // if (/s3021\.jsp/.test(datas.uri))
                    //     console.log(PGNM,datalen, buffer.slice(ret.offset).toString()+":" );
                    if (ptime > datas.stime)
                        datas.rtime = ptime;
                    let pi = buffer.indexOf("\r\n\r\n");
                    if (pi == -1) {
                        pi = ret.offset;
                    };
                    let res = buffer.slice(ret.offset, pi).toString()
                    if (res.match(/Content-Type:\s*image/)) {
                        myMap.delete(ky);
                        // console.log(PGNM,res) ;
                        return;
                    };
                    if (/^HTTP\/.+/s.test(res)) datas.rhead = res;

                    let rcode = /^HTTP.+?\s(\d+?)\s(?:.*Content-Length:\s?(\d+))?\s/s.exec(res);
                    if (rcode) {
                        datas.rcode = Number(rcode[1]);
                        datas.rlen = Number(rcode[2]) || datalen;
                        datas.rdata = bufTrim(buffer.slice(pi, ret.offset + datalen));
                        // datas.rdata = buffer.slice(ret.offset, ret.offset + datalen);
                        // console.log(PGNM,datas );
                        // console.log(PGNM,datas.rdata.toString() );
                    } else {
                        if (datas.rdata)
                            // datas.rdata = Buffer.concat([datas.rdata, bufTrim( buffer.slice(ret.offset, ret.offset + datalen) )])  ;
                            datas.rdata = Buffer.concat([datas.rdata, bufTrim(buffer.slice(ret.offset))]);
                        else
                            datas.rdata = buffer.slice(ret.offset);
                    };

                    if (datalen == 5 || datas.rlen > 0 && (datas.rdata.length >= (MAX_RESP_LEN >= datas.rlen ? MAX_RESP_LEN : datas.rlen))) {
                        // datas.rdata = bufTrim(datas.rdata);
                        con.query("INSERT INTO TTCPPACKET \
                            (TCODE, CMPID,O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,RHEAD,slen,rlen,SDATA,RDATA) \
                            values \
                            (?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?) ;",
                            [cn_tcode, datas.seqno, datas.o_stime, datas.stime, datas.rtime, datas.srcip, datas.srcport, datas.dstip, datas.dstport, 1,
                                datas.method, datas.uri, datas.seqno, datas.ackno, datas.rcode, datas.rhead, datas.slen,
                                datas.rlen > datas.rdata.length ? datas.rlen : datas.rdata.length, datas.sdata, datas.rdata],
                            (err, dt) => {
                                if (err)
                                    console.error("?? insert error ", err, datas.uri);
                                else {
                                    // console.log(PGNM,"** insert ok ", datas.uri);
                                    icnt++ ;
                                }
                            }
                        );
                        myMap.delete(ky);
                    } else {
                        myMap.set(ky, datas);
                    }
                }

            } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
                console.log(PGNM,'Decoding UDP ...');

                ret = decoders.UDP(buffer, ret.offset);
                console.log(PGNM,' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);

                console.log(PGNM,buffer.toString('binary', ret.offset, ret.offset + ret.info.length));
            } else
                console.log(PGNM,'Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
        } else
            console.log(PGNM,'Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);


    });

    parser.on('end', () => endprog(cn_tcode, p_func));

}

function bufTrim(buf) {
    // let pi = buf.length > 100 ? 100 : buf.length;
    if (buf.indexOf('0\r\n\r\n') == 0)
        return Buffer.from('');
    let str = buf.toString();
    str = str.replace(/^\s+/, '');
    str = str.replace(/^[0-9a-fA-F]+\r\n\s*/, '');
    // return Buffer.concat([Buffer.from(str), buf.slice(pi)]);
    return Buffer.from(str);
}
function endprog(p_tcode, p_func) {
    let cnt = 0;
    let tcnt = myMap.size;
    myMap.forEach((datas, ky) => {
        if (datas.rdata) {
            datas.rdata = bufTrim(datas.rdata);
            con.query("INSERT INTO TTCPPACKET \
                (TCODE,CMPID, O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,RHEAD,slen,rlen,SDATA,RDATA) \
                values \
                (?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?) ;",
                [p_tcode, datas.seqno, datas.o_stime, datas.stime, datas.rtime, datas.srcip, datas.srcport, datas.dstip, datas.dstport, 1,
                    datas.method, datas.uri, datas.seqno, datas.ackno, datas.rcode, datas.rhead, datas.slen,
                    datas.rlen > datas.rdata.length ? datas.rlen : datas.rdata.length, datas.sdata, datas.rdata],
                (err, dt) => {

                    if (err)
                        console.error("?? insert error ", err, datas.uri);
                    else {
                        icnt++ ;
                        // console.log(PGNM,"** last insert ok ", datas.uri);
                    }

                }
            );
        };
        cnt++;
        myMap.delete(ky);
    });

    let ival = setInterval(() => {
        console.log(PGNM,tcnt, cnt);
        if (cnt >= tcnt) {
            con.query('call sp_summary(?)',[p_tcode]) ;
            console.log(PGNM,"*** Import completed ***");
            clearInterval(ival);
            p_func(icnt + "건 Import") ;
        }
    }, 3000);

    // child.kill('SIGINT') ;

    // setTimeout( process.exit, 0) ;

    // hid.close() ;
} 
