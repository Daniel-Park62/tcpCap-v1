#!/bin/bash

mysql -uaqtdb -pDawinit1! -N -Daqtdb -se"select pkey, tcode, tnum,dbskip, exectype,etc from texecjob WHERE reqstartdt <= NOW() and result=0 order by reqstartdt LIMIT 1" | \
while IFS=" " read pkey tcode tnum dbskip exectype etc
do
  COND="TCODE='$tcode'" ;
  echo " etc => [$etc]" ;
  [ ${#etc} -gt 6 ] && COND="$COND AND $etc" ;
  echo $COND ;
  tcnt=`mysql -uaqtdb -pDawinit1! -N -Daqtdb -e"SELECT count(1) from ttransaction a where $COND"` ;
  if [ $tnum -gt 1 ]; then
    pcnt=$(echo "$tcnt $tnum" | awk '{printf "%.0f", $1 / $2 + 0.9}') ;
  else
    pcnt=$tcnt ;
  fi

  COND="" ;
  if [ ${#etc} -gt 6 ]; then
    COND="-e \"$etc\"" ;
  fi

  if [ ${exectype} -eq 1 ]; then
    COND="-k $COND" ;
  fi

  for (( i=0 ;i<tcnt ; i+=pcnt))
  do
    (echo ".aqt_send2 -j $tcode $COND -u $i,$pcnt >/dev/null " | sh -v )  &
  done
  mysql -uaqtdb -pDawinit1! -N -Daqtdb -se"UPDATE texecjob SET resultstat = 1, startDt=NOW(), endDt=NULL WHERE pkey=$pkey; commit;" ;
  wait ;
  mysql -uaqtdb -pDawinit1! -N -Daqtdb -se"UPDATE texecjob SET resultstat = 2, endDt=NOW() WHERE pkey=$pkey; commit;" ;
done

exit 0 ;
