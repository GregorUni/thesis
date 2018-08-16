sudo modprobe -r macsec
sudo rmmod /lib/modules/$(uname -r)/kernel/crypto/aegis128l.ko
sudo make -C /lib/modules/$(uname -r)/build M=$(pwd) aegis128l.ko
sudo cp aegis128l.ko /lib/modules/$(uname -r)/kernel/crypto
sudo insmod /lib/modules/$(uname -r)/kernel/crypto/aegis128l.ko
cd ~
#cd /home/test1/linux-4.16.16/drivers/net
#sudo bash imkernel.sh

