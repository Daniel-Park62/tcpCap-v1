#!/bin/bash

while :
do
  mysql -uaqtdb -pDawinit1! -N -Daqtdb -se"SELECT a.pkey, a.tcode, m.lvl FROM trequest a join tmaster m on a.tcode = m.code " | while read pkey tcode LVL
  do
    echo "$pkey $tcode $LVL";
    if [ "${LVL}" != "2" ]; then LVL=""; fi
    ./aqt_send${LVL} -j $tcode -e "a.pkey = $pkey"
    mysql -uaqtdb -pDawinit1! -N -Daqtdb -se"delete from trequest where pkey = $pkey ; commot ;" ;
  done
  sleep 5;
done
