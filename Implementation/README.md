# Implementation
**Low Latency-Kryptographie für transparente Layer 2 - Verschlüsselung mit MACsec**

Hier sind die Implemtationen aufzufinden. Bevor man das MACsec.c starten kann muss man iproute2 auf dem System konfigurieren.
Wie man das macht, ist unter dem [Link](https://nextheader.net/2016/10/14/macsec-on-linux/) erklärt. 
Des Weiteren muss man die ipmacsec.c Datei im iproute2 austauschen. Danach wird die Kernel Version heruntergeladen, 
die auf dem Linux Betriebssystem benutzt wird. Dann wird die MACsec.c Datei im Ordner macsec ausgetauscht und das imkernel.sh wird gestartet.
