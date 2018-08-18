#!/bin/bash

EVA_DIR=eva
FPREFIX=$(date +%s)
DEST_IP=10.10.12.2
REMOTE_IP=141.76.55.202
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
    ssh root@$REMOTE_IP "killall -q iperf3"
    ssh root@$REMOTE_IP "nohup iperf3 -s > /dev/null 2>&1 &"
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
  #echo -e "${GREEN}Start RTT Evaluation of $1 with MTU $2${NC}"
  PING_FILE=$EVA_DIR/final-$FPREFIX-$1-$2-ping.txt

  timeout 360 ping -A $3 -c 50 -s $((($2 - 8 )))  >> $PING_FILE

}


eva_iperf() {
    echo -e "${GREEN}Start Bandwith Evaluation of $2 with MTU $3${NC}"
    BANDWIDTH_FILE=$EVA_DIR/final-$FPREFIX-$1-$2-iperf.json

    echo -n "[" > $BANDWIDTH_FILE # Clear file

    for i in `seq 1 $1`; do
        echo -e "Start iperf3 #$i"
        timeout 20 iperf3 -Jc $4 -b0 -V >> $BANDWIDTH_FILE
        #iperf3 -c 1.1.1.1 -b 0 -V
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

	if [[ $5 == mwe ]]; then #case macsec with aes(gcm) without encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_without_encryption.sh"
                config_macsec_without_encryption
                make_info $2 $4
               	eva_ping $2 $4 $IP
                eva_iperf $1 $2 $4 $DEST_IP
	

	elif [[ $5 == med ]]; then #case macsec with aes(gcm) and encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_encryption_default.sh"
		config_macsec_encryption_default
		make_info $2 $4
		eva_ping $2 $4 $IP
		eva_iperf $1 $2 $4 $DEST_IP

	elif [[ $5 == cwe ]]; then #case macsec with chachapoly without encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_chacha_without_encryption.sh"
		config_macsec_chacha_without_encryption
		make_info $2 $4
		eva_ping $2 $4 $IP
		eva_iperf $1 $2 $4 $DEST_IP

	elif [[ $5 == mce ]]; then #case macsec with chachapoly and encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_chacha_encryption.sh"
		config_macsec_chacha_without_encryption
		make_info $2 $4
		eva_ping $2 $4 $IP
		eva_iperf $1 $2 $4 $DEST_IP

	elif [[ $5 == awe ]]; then #case macsec with aegis128l without encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_aegis128l_without_encryption.sh"
		config_macsec_aegis128l_without_encryption
		make_info $2 $4
		eva_ping $2 $4 $IP
		eva_iperf $1 $2 $4 $DEST_IP

	elif [[ $5 == mmwe ]]; then  #case macsec with morus640 without encryption
		IP=$DEST_IP
		ssh root@$REMOTE_IP "sh /home/test-2/thesis/evaluation/config_macsec_morus640_without_encryption.sh"
		config_macsec_morus640_without_encryption
		make_info $2 $4
		eva_ping $2 $4 $IP
		eva_iperf $1 $2 $4 $DEST_IP


	else    #case no macsec no encryption
	        IP=169.254.234.92
                make_info $2 $4
                eva_ping $2 $4 $IP
                eva_iperf $1 $2 $4 $IP

	fi
}

config_macsec_without_encryption()
{
	sudo modprobe -r macsec
	sudo modprobe -v macsec
	sudo ip link add link eno1 macsec0 type macsec
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012	
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt off


}

config_macsec_encryption_default()
{
	sudo modprobe -r macsec
	sudo modprobe -v macsec
	sudo ip link add link eno1 macsec0 type macsec
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt on
}

config_macsec_chacha_without_encryption()
{
	sudo modprobe -r macsec
	sudo modprobe -v macsec
	sudo modprobe -v chacha20poly1305
	sudo ip link add link eno1 macsec0 type macsec cipher chacha-poly-256
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt off
}

config_macsec_chacha_encryption()
{
	sudo modprobe -r macsec
	sudo modprobe -v macsec
	sudo modprobe -v chacha20poly1305
	sudo ip link add link eno1 macsec0 type macsec cipher chacha-poly-256
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt on
}

config_macsec_aegis128l_without_encryption()
{
	sudo modprobe -r macsec
	

	sudo cd /home/test1/linux-4.16.16/crypto
	sudo bash aegis128l.sh
	sudo cd ~

	sudo modprobe -v macsec
	#sudo modprobe -v aegis128l
	sudo ip link add link eno1 macsec0 type macsec cipher aegis128l-128
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt off
}

config_macsec_morus640_without_encryption()
{
	sudo modprobe -r macsec
	

	sudo cd /home/test1/linux-4.16.16/crypto
	sudo bash morus.sh
	sudo cd ~
	
	sudo modprobe -v macsec
	#sudo modprobe -v morus640
	sudo ip link add link eno1 macsec0 type macsec cipher morus640-128
	sudo ip macsec add macsec0 tx sa 0 pn 1 on key 01 12345678901234567890123456789012
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1
	sudo ip macsec add macsec0 rx address 08:00:27:19:58:33 port 1 sa 0 pn 1 on key 02 09876543210987654321098765432109
	sudo ip link set dev macsec0 up
	sudo ifconfig macsec0 10.10.12.1/24
	sudo ip link set macsec0 type macsec encrypt off
}

# first parameter is the value for the 
# second parameter give a short explanation
# third parameter gives the mtu
# fourth parameter gives the packet size
init
make_info
eva 1 "no-macsec" 1000 1468
eva 1 "macsec-aes(gcm)-we" 1000 1468 mwe
eva 1 "macsec-aes(gcm)-e" 1000 1468 med
eva 1 "macsec-chachapoly-we" 1000 1468 cwe
eva 1 "macsec-chachapoly-e" 1000 1468 mce
eva 1 "macsec-aegis128l-we" 1000 1468 awe
eva 1 "macsec-morus640-we" 1000	1468 mmwe
