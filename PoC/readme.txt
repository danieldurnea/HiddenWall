This is test code for PoC, to study how to create module using hook with netfilter... 

For original code and generate your module, please read the intro paper of HiddenWall.

To the test run:

# make clean; make

# insmod hiddenwall.ko

TO turn test module visible run:
# echo "AbraKadabra" > /dev/fake_char

Tested with nmap with IPV6:

---
Artorias:/home/cold_heart/c/HiddenWall/PoC# nmap -sT -Pn ::1 -p21,22,23,80,443,1337 -6

Starting Nmap 7.01 ( https://nmap.org ) at 2019-05-11 22:03 -03
Nmap scan report for ip6-localhost (::1)
Host is up (0.000097s latency).
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   filtered ssh
23/tcp   filtered telnet
80/tcp   open     http
443/tcp  open     https
1337/tcp closed   waste

---
