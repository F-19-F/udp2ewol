# udp2ewol
## A simple daemon listen udp port and send ethernet wol packet to udp wol packet want to send
## it makes you easy to wake on wan without arp bind.
### How to use(Always running on a router,ini.d file is for openwrt).
#### ssh to your router(openwrt)
```
wget https://github.com/F-19-F/udp2ewol/archive/refs/heads/master.zip
unzip master.zip
cd udp2ewol-master
make 
make install
/etc/init.d/udp2ewol start
# if no error ,then start on startup
/etc/init.d/udp2ewol enable
```
## TODO
### 1.IPV6 support
### 2.pkg for openwrt

## Thanks
### [CLOG](https://github.com/mmueller/clog)