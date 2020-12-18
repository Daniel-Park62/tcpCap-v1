use aqtdb ;

SET @@session.autocommit =1;

LOAD DATA LOCAL INFILE 'blabla'
 IGNORE
 INTO TABLE tloaddata columns TERMINATED BY '^^'
 LINES TERMINATED BY '@@\n' (@slen, @uuid, @svrnm, @svcid, @stime, @rtime, @userid, @clntip, @scrno
                             @sdata,@rlen, @msgcd, @rcvmsg,@rdata)
 SET uuid=@uuid, svrnm=@svrnm,svcid=@svcid,o_stime=STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f'),
     stime=STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f'),rtime=STR_TO_DATE(@rtime,'%Y%m%d%H%i%S%f'), userid=@userid,
     clientip=@clntip, scrno=@scrno, sdata=@sdata,slen=@slen, rlen=@rlen, msgcd=@msgcd,rcvmsg=@rcvmsg, rdata=@rdata,
     elapsed = TIME_TO_SEC(TIMEDIFF(STR_TO_DATE(@rtime,'%Y%m%d%H%i%S%f'), STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f') )),
     svctime = TIME_TO_SEC(TIMEDIFF(STR_TO_DATE(@rtime,'%Y%m%d%H%i%S%f'), STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f') )),
     cdate= now(), sflag='1' ;
     
