"use strict";

const MAX_RESP_LEN = 1024 * 1024 * 2;
const SIZE_BLOB = 1024 * 1024 * 2; 
const PGNM = '[capToDb]';

let myMap = null;
let myMap_s = null;
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
    myMap = new Map();
    myMap_s = new Map();
    const { spawn } = require('child_process');

    const util = require('util');
    const pcapp = require('./pcap-parser');

    const moment = require('moment');
    const decoders = require('./Decoders')
    const PROTOCOL = decoders.PROTOCOL;
    const fs = require('fs');
    let dstobj;
    icnt = 0 ;
    console.log("%s Start 테스트id(%s) 입력파일(%s)", PGNM,cn_tcode, dstv);

    try {
        fs.statSync(dstv);
        dstobj = dstv;
    } catch (err) {
        console.log(PGNM,err);
        const child = spawn("tcpdump -s0 -n -w - ", ['tcp && tcp[13]&24 != 0 && host', dstv], { shell: true });
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
                let ky = util.format('%s:%d:%d', srcip, ret.info.srcport, Math.floor(ret.info.ackno/100));
                let sky = util.format('%s:%d:%s:%d', srcip, ret.info.srcport, dstip, ret.info.dstport );
                
                if (/^(GET|POST|DELETE|PUT|PATCH)\s/.test(buffer.slice(ret.offset, ret.offset + 10).toString())) {
                    // let sdata = buffer.slice(ret.offset, ret.offset + datalen);
                    let sdata = buffer.slice(ret.offset);
                    let mdata = /^(GET|POST|DELETE|PUT|PATCH)\s+(\S+?)[?\s](?:.*Content-Length:\s*(\d+)|.*)?/s.exec(sdata.toString());
                    if (mdata == undefined) {
                        console.log(PGNM,sdata.toString());
                        return;
                    }

                    if (/\.(css|js|ico|png|jpg|gif|png|pdf|html)$/i.test(mdata[2]) ) return ;

                    let clen = mdata[3] ? Number(mdata[3]) : 0 ;

                    let datas = {
                        tcode: cn_tcode,
                        method: mdata[1],
                        uri: decodeURIComponent(mdata[2].replace(/(.+)\/$/,'$1')) ,
                        o_stime: ptime,
                        stime: ptime,
                        rtime: ptime,
                        sdata: sdata,
                        slen: datalen,
                        shlen: clen,
                        rlen: -1,
                        srcip: srcip,
                        dstip: dstip,
                        srcport: ret.info.srcport,
                        dstport: ret.info.dstport,
                        seqno: ret.info.seqno,
                        ackno: ret.info.ackno,
                        rhead: '',
                        rdata: '',
                        rcode: 0,
                        isUTF8: true
                    };

                    clen = 0;
                    ky = util.format('%s:%d:%d', dstip, ret.info.dstport, Math.floor((ret.info.seqno + datalen + clen)/100) );
                    
                    myMap.set(ky, datas);
                    myMap_s.set(sky,ky);

                } else if (myMap.has(ky)) {

                    let datas = myMap.get(ky);
                    // if (/s3021\.jsp/.test(datas.uri))
                    //     console.log(PGNM,datalen, buffer.slice(ret.offset).toString()+":" );
                    if (ptime > datas.stime)
                        datas.rtime = ptime;
                    let pi = buffer.indexOf("\r\n\r\n");
                    let res = '';
                    if (pi == -1) {
                        pi = ret.offset;
                        res = buffer.slice(ret.offset).toString() ;
                    } else {
                        res = buffer.slice(ret.offset, pi).toString() ;
                    };
                    
                    if (res.match(/Content-Type:\s*image/)) {
                        myMap.delete(ky);
                        // console.log(PGNM,res) ;
                        return;
                    };
                    if (/^HTTP\/.+/s.test(res)) {
                        datas.rhead = res;
                        datas.isUTF8 = ! /charset=euc-kr/si.test(res) ;
                    } else
                        pi = ret.offset;

                    let rcode = /^HTTP.+?\s(\d+?)\s(?:.*Content-Length:\s*(\d+)|.*)?/s.exec(res);
                    let rval = {} ;
                    if (rcode) {
                        // datalen -= res.length ;
                        datas.rcode = Number(rcode[1]);
                        datas.rlen = rcode[2] ? Number(rcode[2]) :  MAX_RESP_LEN  ;
                        // rval = bufTrim2(buffer.slice(pi )) ;
                        // datas.rdata = rval.data ;
                        // datas.rdata = bufTrim(buffer.slice(pi, ret.offset + datalen));
                        // datas.rdata = buffer.slice(ret.offset, ret.offset + datalen);
                        // console.log(PGNM,"(1)",buffer.slice(pi, ret.offset + datalen).toString() );
                        // console.log(PGNM,"(2)",datas.rdata.toString() );
                    };
                    // if (datas.seqno == 995092230) console.log("@@" + buffer.slice(pi,pi+100 ).toString());
                    
                    rval = bufTrimN(buffer.slice(pi ), datas.isUTF8 ) ;

                    if (datas.rdata.length > 0)
                        // datas.rdata = Buffer.concat([datas.rdata, bufTrim(buffer.slice(ret.offset))]);
                        datas.rdata = Buffer.concat([datas.rdata, rval.data]);
                    else
                        // datas.rdata = buffer.slice(ret.offset);
                        datas.rdata = rval.data ;

                        // console.log(PGNM,"(1)",buffer.slice(pi, ret.offset).toString().trim() );
                        // console.log(PGNM,"(2)",rval.chk, rval.data.toString() );
    
                    // if ( datas.seqno == 1202683084) console.log("[%s]", buffer.slice(pi ).toString() );

                    // if (rval.chk || datas.rlen > 0 && (datas.rdata.length >= (MAX_RESP_LEN >= datas.rlen ? MAX_RESP_LEN : datas.rlen))) {
                    if (rval.chk || datas.rlen == 0 || datas.rdata.length >=  datas.rlen) {
                        // datas.rdata = bufTrim(datas.rdata);
                        con.query("INSERT INTO TTCPPACKET \
                            (TCODE, CMPID,O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,RHEAD,slen,rlen,SDATA,RDATA) \
                            values \
                            (?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?) ;",
                            [cn_tcode, datas.seqno, datas.o_stime, datas.stime, datas.rtime, datas.srcip, datas.srcport, datas.dstip, datas.dstport, 1,
                                datas.method, datas.uri, datas.seqno, datas.ackno, datas.rcode, datas.rhead, datas.slen,
                                datas.rdata.length , datas.sdata.slice(0,SIZE_BLOB), datas.rdata],
                            (err, dt) => {
                                if (err) {
                                    console.error(" insert error size(%d)",datas.rdata.length + datas.sdata.length, err, datas.uri);
                                    process.emit('SIGINT') ;
                                } else {
                                    icnt++ ;
                                    icnt % 100 == 0 && console.log(PGNM + "** insert ok %d 건", icnt, datas.uri);
                                }
                            }
                        );
                        myMap.delete(ky);
                    } else {
                        myMap.set(ky, datas);
                    }
                } else if (myMap_s.has(sky)  && myMap.has(myMap_s.get(sky) ) ) {
                    let datas = myMap.get(myMap_s.get(sky)) ;
                    let pi = datas.sdata.indexOf("\r\n\r\n") ;
                    if (pi >= 0 && datas.shlen > 0 && datas.sdata.slice(pi+4).length >= datas.shlen) return ;
                    myMap.delete(myMap_s.get(sky)) ;
                    let ky2 = util.format('%s:%d:%d', dstip, ret.info.dstport, Math.floor((ret.info.seqno + datalen )/100) );
                    datas.sdata = Buffer.concat([datas.sdata, buffer.slice(ret.offset)]) ;
                    datas.slen = datas.sdata.length ;
                    myMap_s.set(sky,ky2)
                    myMap.set(ky2, datas) ;
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
    const iconv = require('iconv-lite');

    function bufTrimN(buf, isUTF8) {
        // let pi = buf.length > 100 ? 100 : buf.length;
        
        if (buf.length == 0)
            return {data:buf, chk:false} ;
    
        let str = isUTF8 ? buf.toString() : iconv.decode(buf, 'EUC-KR').toString() ;
            // str = str.trim();
        // let rstr = /^\s*([0-9a-fA-F]+)\r\n\s*/s.exec(str) ;
        // let sz = parseInt( /^\s*([0-9a-fA-F]+)\r\n\s*/s.exec(str) [1], 16) || 0 ;
        let rval = {  chk : (/\n0+\r\n\s*$/s.test(str)) } ;
        // if (rval.chk)
        //     console.log("**", rval.chk ,str.length, str) ;
        //str = str.replace(/\s0\r\n\s*$/s, '');
        str = str.replace(/^(\r\n)?[0-9a-fA-F]{1,4}\r\n/ms, '');
        str = str.trim();
        rval.data = Buffer.from(str) ;
    
        return rval ;
    }
    

}

function bufTrim2(buf) {
    // let pi = buf.length > 100 ? 100 : buf.length;
    
    if (buf.length == 0)
        return {data:buf, chk:false} ;

    let str = buf.toString();
        // str = str.trim();
    // let rstr = /^\s*([0-9a-fA-F]+)\r\n\s*/s.exec(str) ;
    // let sz = parseInt( /^\s*([0-9a-fA-F]+)\r\n\s*/s.exec(str) [1], 16) || 0 ;
    let rval = {  chk : (/\n0+\r\n\s*$/s.test(str)) } ;
    // if (rval.chk)
    //     console.log("**", rval.chk ,str.length, str) ;
    //str = str.replace(/\s0\r\n\s*$/s, '');
    str = str.replace(/^(\r\n)?[0-9a-fA-F]{1,4}\r\n/ms, '');
    str = str.trim();
    rval.data = Buffer.from(str) ;

    return rval ;
}

function endprog(p_tcode, p_func) {
    let cnt = 0;
    let tcnt = myMap.size;
    myMap.forEach((datas, ky) => {
        // if (datas.rhead.length == 0)  datas.rhead = 'No Data' ;
        if (datas.rhead.length > 0 || datas.rdata.length > 0) {
            // datas.rdata = bufTrim(datas.rdata);
            con.query("INSERT INTO TTCPPACKET \
                (TCODE,CMPID, O_STIME,STIME,RTIME, SRCIP,SRCPORT,DSTIP,DSTPORT,PROTO, METHOD,URI,SEQNO,ACKNO,RCODE,RHEAD,slen,rlen,SDATA,RDATA) \
                values \
                (?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?) ;",
                [p_tcode, datas.seqno, datas.o_stime, datas.stime, datas.rtime, datas.srcip, datas.srcport, datas.dstip, datas.dstport, 1,
                    datas.method, datas.uri, datas.seqno, datas.ackno, datas.rcode, datas.rhead, datas.slen,
                    datas.rdata.length , datas.sdata.slice(0,SIZE_BLOB), datas.rdata],
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

    let ival = setInterval(async () => {
        console.log(PGNM,tcnt, cnt);
        if (cnt >= tcnt) {
            await con.query('call sp_summary(?)',[p_tcode]) ;
            console.log("%s *** Import completed (%d 건)***", PGNM, icnt);
            clearInterval(ival);
            p_func(icnt + "건 Import") ;
        }
    }, 3000);

    // child.kill('SIGINT') ;

    // setTimeout( process.exit, 0) ;

    // hid.close() ;
} 
