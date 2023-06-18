# HiddenWall
<img align="center" src="https://github.com/CoolerVoid/HiddenWall/blob/master/doc/hiddenwallCMD.png?raw=true">

HiddenWall is a Linux kernel module generator for custom rules with netfilter. (block ports, Hidden mode, firewall functions, etc.).
<img align="right" width="240" height="220" src="https://github.com/CoolerVoid/HiddenWall/blob/master/doc/wall.png">
The motivation: in a bad situation, an attacker can put your iptables/ufw to fall. But if you have HiddenWall, 
the attacker will not find the hidden kernel module that blocks external access because it has a hook to netfilter on kernel land(think like a second layer for Firewall).

My beginning purpose at this project is to protect my server, and now it is to protect my friends' machines.
When I talk to friends, I say peoples that don't know how to write low-level code. Using the HiddenWall, you can 
generate your custom kernel module for your firewall configuration. 

The low-level programmer can write new templates for modules etc.

VIDEO DEMO:
--
https://www.youtube.com/watch?v=QA0jvFTULAk


The first step, understand before the run
--

Verify if the kernel version is 3.x, 4.x, or 5.x:
```
uname -r
```

Clone the repository
```
git clone https://github.com/CoolerVoid/HiddenWall
```

Enter the folder
```
cd HiddenWall/module_generator
```

Edit your firewall rules in directory rules/server.YAML, the python scripts, use that file to generate a new firewall module.

```
$ cat rules/server.yaml
module_name: SandWall
public_ports: 80,443,53
unhide_key: AbraKadabra
hide_key: Shazam
fake_device_name: usb14
liberate_in_2_out: True
whitelist: 
- machine: 
   ip: 192.168.100.181
   open_ports: 22,21
- machine:
   ip: 192.168.100.22
   open_ports: 22

```

If you want to study the static code to generate, look at the content at directory "templates".




The second step, generate your module
--

If you want to generate a kernel module following your YAML file of rules, follow that command:

```
$ python3 WallGen.py --template template/hiddenwall.c -r rules/server.yaml
```
This action can generate a generic module with the rules of the server.YAML, if you want to use another template, you can use "wall.c", so the template module "hidden wall" has the option to run on hidden mode(is not visible to "# lsmod" for example).



The third step, install your module.
--

If you use Fedora Linux, install kernel packages for developer:
```
# dnf update
# dnf install kernel-headers.x86_64 kernel-modules.x86_64 kernel.x86_64 kernel-devel kmod
```
On Ubuntu Linux:
```
apt install linux-headers-generic gcc make
```
To test module:
```
# cd output; make clean; make
# insmod SandWall.ko
```

YAML's rule to generate module is simple, drop all out to in packets, accept ports 80,443, and 53. The machine 192*.181 can connect at ports 22 and 21.

If you use Nmap at localhost/127.0.0.1, you can view the ports open because rule liberate_in_2_out is true.

The password to turn Firewall visible is "AbraKadabra".

The password to turn the Firewall invisible is "Shazam".

You need to send the password for your fake device, "usb14".

To exit the module, you need to turn visible at the "lsmod" command ...

```
# echo "AbraKadabra" > /dev/usb14
# lsmod | grep SandWall
# rmmod SandWall
```


Random notes
--

Tested on ubuntu 16 and fedora 29 at kernels "3.x","4.x" and "5.x".


TODO
--

Support to IPV6. 
Macro selects the interface(to use multiple modes for each interface).
Option to remove last logs when turn hides mode.
Option to search and remove other toolkits.
Code generator to BFP...

## Point of attention
The purpose of this tool is to use in pentest, take attention if you have a proper authorization before to use that. I do not have responsibility for your actions. You can use a hammer to construct a house or destroy it, choose the law path, don't be a bad guy, remember.


References
--

*Wikipedia Netfilter* 
https://en.wikipedia.org/wiki/Netfilter

*Linux Device Drivers* 
http://lwn.net/Kernel/LDD3/

*M0nad's Diamorphine* 
https://github.com/m0nad/Diamorphine/
