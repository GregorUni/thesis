#!/bin/bash

EVA_DIR=eva
FPREFIX=$(date +%s)
DEST_IP=10.10.12.1
REMOTE_IP=192.168.56.101
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

init() {
    if [ ! -d "$EVA_DIR" ]; then
        mkdir $EVA_DIR
    fi
    init_remote
}

init_remote() {
    echo -e "${GREEN}Init Remote${NC}"
    killall -q iperf3
    nohup iperf3 -s > /dev/null 2>&1 &
}

make_info() {
  echo -e "${GREEN}Write current info"
  INFO_FILE=$EVA_DIR/final-$FPREFIX-$1-$2.info

  tc qdisc > $INFO_FILE
	ip link show macsec0 >> $INFO_FILE
	ip link show enp0s3 >> $INFO_FILE
	ip macsec show >> $INFO_FILE
}


eva_ping() {
  echo -e "${GREEN}Start RTT Evaluation of $1 with MTU $2${NC}"
  PING_FILE=$EVA_DIR/final-$FPREFIX-$1-$2-ping.txt

  timeout 360 ping -A $3 -c 50 -s $((($2 - 8 )))  >> $PING_FILE
}

eva_iperf() {
	echo -e "${GREEN}Start Bandwith Evaluation of $2 with MTU $3${NC}"
	echo -e "Erster Parameter:$1 Zweiter:$2 Dritter:$3 Vierter:$4"
	BANDWIDTH_FILE=$EVA_DIR/final-$FPREFIX-$1-$2-iperf.json

	echo -n "[" > $BANDWIDTH_FILE # Clear file

	for i in `seq 1 $1`; do
        	echo -e "Start iperf3 #$i"
		timeout 20 iperf3 -c $IP -V -t19  >> $BANDWIDTH_FILE
		if [ $? -ne 0 ]; then
		echo -e "${RED}iperf3 error${NC}"
	 	#exit 1
		fi

		if [ $1 -eq $i ]; then
			echo -ne "]" >> $BANDWIDTH_FILE
        	else
            		echo -ne "," >> $BANDWIDTH_FILE
       		fi;
    	done
}

eva() {
	 echo -e "Erster Parameter:$1 Zweiter:$2 Dritter:$3 Vierter:$4 Fünfter: $5"
	if [[ $5 == m ]]; then
		echo -e "Ich war hier"
		IP=$DEST_IP
                config_macsec_without_encryption
                make_info $2 $4
                eva_ping $2 $4 $IP
                eva_iperf $1 $2 $4 $IP


	else
                IP=$REMOTE_IP
		echo 
                make_info $2 $4
                eva_ping $2 $4 $IP
                eva_iperf $1 $2 $4 $IP

	fi
}

config_macsec_without_encryption()
{
	sudo modprobe -r macsec
	sudo modprobe -v macsec
	sudo ip link add link enp0s3 macsec0 type macsec
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:c4:23:63 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:c4:23:63 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.2/24
}


init
make_info
eva 4 "no-macsec" 1000 1468
eva 4 "macsec" 1000 1468 m
