sudo modprobe -r macsec
sudo rmmod /lib/modules/$(uname -r)/kernel/crypto/morus640.ko
sudo make -C /lib/modules/$(uname -r)/build M=$(pwd) morus640.ko
sudo cp morus640.ko /lib/modules/$(uname -r)/kernel/crypto 
sudo insmod /lib/modules/$(uname -r)/kernel/crypto/morus640.ko

cd ~
#cd /home/test1/linux-4.16.16/drivers/net
#sudo bash imkernel.sh

