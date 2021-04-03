#!/bin/sh /etc/rc.common
START=99
start() {        
    /usr/bin/udp2ewol
}                 

stop() {          
    killall udp2ewol
}