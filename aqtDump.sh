#!/bin/bash

if [ $1"" == "-h" ]
then 
	cat <<EOF
사용법:
	$0 월일 dump건수 일수
	ex) $0 0415 10000 4
	덤프파일명 xxx_0415.pcap 으로 패킷 10,000건이 될때까지 수행하며 4일후 강제종료함
	(건수지정하지 않으면 100,000 , 일수 미지정시 5일후 종료됨)
EOF
	exit ;
fi

trap 

MD=`date +%m%d`
CNT=100000
[ $1 ] && MD=$1;
[[ $2 =~ ^[0-9]+$ ]] && CNT=$2;
ENDDT=`date +"%Y%m%d%k%M" -d '5 day'`
[[ $3 =~ ^[0-9]+$ ]] && ENDDT=`date +"%Y%m%d%k%M" -d "$3 day'"`

echo "*input -> (${MD}) (${CNT}) ($ENDDT)"

mkdir -p out

tcpdump -n -c${CNT} -w out/aa_${MD}.pcap "tcp && tcp[13] & 24 != 0 && host 192 && port (80)"  &
tcpdump -n -c${CNT} -w out/bb_${MD}.pcap "tcp && tcp[13] & 24 != 0 && host 192 && port (443)"  &

while [[ `date +"%Y%m%d%k%M"` < $ENDDT ]]
do
	sleep 3
done

kill -9 `ps -ef|awk '/tcpdump/ && !/awk/ {printf "%d ",$2}'`
