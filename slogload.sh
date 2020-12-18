
if [ $# -lt 1 ];then
  echo "사용법: $0 대상로그파일명" ;
  exit ;
fi
mysql -uaqtdb -pDawinit1! -N -s <<EOFL

use aqtdb ;

CREATE TEPORARY TABLE TEMP_TR LIKE ttransaction ;
SET @@session.autocommit=1;

LOAD DATA LOCAL INFILE '$1'
 replace
 INTO TABLE TEMP_TR columns TERMINATED BY '^^'
 LINES TERMINATED BY '@@\n' ( @pkey, @stime, @rtime, @gap, @msgcd,@rlen, @rdata)
 SET pkey=@pkey, stime=STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f'),
     rtime=STR_TO_DATE(@rtime,'%Y%m%d%H%i%S%f'), elapsed=@gap, svctime=@gap,
     msgcd=@msgcd, sflag='1', rlen=@rlen, rdata=@rdata ;

UPDATE ttransaction JOIN TEMP_TR ON ttransaction.pkey = TEMP_TR.pkey
  SET ttransaction.stime = TEMP_TR.stime ,
      ttransaction.rtime = TEMP_TR.rtime ,
      ttransaction.msgcd = TEMP_TR.msgcd ,
      ttransaction.elapsed = TEMP_TR.elapsed ,
      ttransaction.svctime = TEMP_TR.svctime ,
      ttransaction.rdata = TEMP_TR.rdata,
      ttransaction.rlen = TEMP_TR.rlen,
      ttransaction.rcvmsg = substr(TEMP_TR.rdata, 256, 80),
      ttransaction.errinfo = null,
      ttransaction.sflag = '1' ;

DROP TEMPORARY TABLE TEMP_TR ;
EOFL
