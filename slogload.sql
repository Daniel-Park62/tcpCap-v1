use aqtdb ;

CREATE TEPORARY TABLE TEMP_TR LIKE ttransaction ;
SET @@session.autocommit=1;

LOAD DATA LOCAL INFILE 'blabla.slog'
 replace
 INTO TABLE TEMP_TR columns TERMINATED BY '^^'
 LINES TERMINATED BY '@@\n' ( @pkey, @stime, @rtime, @gap, @msgcd, @rdata)
 SET pkey=@pkey, stime=STR_TO_DATE(@stime,'%Y%m%d%H%i%S%f'),
     rtime=STR_TO_DATE(@rtime,'%Y%m%d%H%i%S%f'), elapsed=@gap, svctime=@gap,
     msgcd=@msgcd, sflag='1', rdata=@rdata ;

UPDATE ttransaction JOIN TEMP_TR ON ttransaction.pkey = TEMP_TR.pkey
  SET ttransaction.stime = TEMP_TR.stime ,
      ttransaction.rtime = TEMP_TR.rtime ,
      ttransaction.msgcd = TEMP_TR.msgcd ,
      ttransaction.elapsed = TEMP_TR.elapsed ,
      ttransaction.svctime = TEMP_TR.svctime ,
      ttransaction.rdata = TEMP_TR.rdata
      ttransaction.sflag = '1' ;
