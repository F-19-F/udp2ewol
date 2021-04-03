#include <linux/if.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
//transform ip and port
#include <arpa/inet.h>
#include <getopt.h>
//just for log
#define CLOG_MAIN
#include "clog.h"
int CLI_OUT = 1; /* Unique identifier for logger */
int CLI_ERROR = 2;
int bind_sock=-1;
static char usage_msg[] =
"usage: udp2ewol [-i <ifname>]\n"
"\n"
"	This program listen udp packet and send a ethernet packet to\n"
"	the address the WOL packet send.It makes you easy to wan on wan\n"
"	without arp bind.\n"
"\n"
"	Options:\n"
"		-i ifname	Use interface IFNAME instead of the default 'eth0' to send packet.\n"
"		-l path		Path to logfile,default: /var/run/udp2ewol.log.\n"
"		-p port		Set the udp to listen,default: 9\n"
"		-n		Don't start daemon.\n"
"		-h		show this message and exit.\n";
/*
SendWolUnity
*/
//get interface's addr
int Getifaddr(char *ifname, unsigned char *addr)
{
    //just get addr
    int s = socket(AF_INET,SOCK_STREAM,0);
    struct ifreq if_hwaddr;
    unsigned char *hwaddr = if_hwaddr.ifr_hwaddr.sa_data;
    strcpy(if_hwaddr.ifr_name, ifname);
    if (ioctl(s, SIOCGIFHWADDR, &if_hwaddr) < 0)
    {
        clog_set_level(CLI_OUT, CLOG_ERROR);
        clog_error(CLOG(CLI_OUT), "SIOCGIFHWADDR on %s failed: %s",ifname,strerror(errno));
        return -1;
    }
    memcpy(addr, hwaddr, sizeof(if_hwaddr.ifr_hwaddr.sa_data));
    close(s);
    return 1;
}
//gen wol packet and return packet size
int GenPacket(unsigned char *src_addr, unsigned char *dest_addr, unsigned char *packet)
{
    int offset = 0;
    memcpy(packet, dest_addr, 6);
    offset += 6;
    memcpy(packet + offset, src_addr, 6);
    offset += 6;
    memset(packet + offset, 0x08, 1);
    offset += 1;
    memset(packet + offset, 0x42, 1);
    offset += 1;
    memset(packet + offset, 0xFF, 6);
    offset += 6;
    //mac_addr*16
    for (int i = 0; i < 16; i++)
    {
        memcpy(packet + offset, dest_addr, 6);
        offset += 6;
    }
    return offset;
}
int SendPkt(char *ifname, unsigned char *packet, int packet_size)
{
    int res=-1;

    int s = socket(PF_PACKET, SOCK_RAW, 0);
    if (s < 0)
    {
        if (errno == EPERM)
        {
            clog_error(CLOG(CLI_OUT),"Sending Ethernet frame needs root privilege");
        }
        else
        {
            clog_error(CLOG(CLI_ERROR),"Ethernet frame socket error : %s",strerror(errno));
        }
        return res;
    }

    struct sockaddr_ll whereto;
    struct ifreq ifr;


    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
    {
        clog_error(CLOG(CLI_ERROR),"SIOCGIFINDEX on %s failed: %s",ifname,strerror(errno));
        return res;
    }


    memset(&whereto, 0, sizeof(whereto));
    whereto.sll_family = AF_PACKET;
    whereto.sll_ifindex = ifr.ifr_ifindex;
    whereto.sll_halen = ETH_ALEN;
    memcpy(whereto.sll_addr, packet, ETH_ALEN);


    res=sendto(s, packet, packet_size, 0, (struct sockaddr *)&whereto, sizeof(whereto));


    close(s);
    
    return res;
}
int SendWol(unsigned char *dest_addr, char *ifname)
{
    int pkt_size = 0;
    //Get if mac
    unsigned char src_addr[14]={0};
    //Gen Packet
    char packet[200] = {0};
    if (Getifaddr(ifname,src_addr)<0)
    {
        clog_error(CLOG(CLI_ERROR),"Unable to get interface %s's addr",ifname);
        return -1;
    }
    pkt_size = GenPacket(src_addr, dest_addr, packet);
    //Send Packet
    if (SendPkt(ifname, packet, pkt_size) > 0)
    {
        clog_info(CLOG(CLI_OUT),"Succeed in sending wol packet to %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x via %s(%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x)",
        dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], dest_addr[4], dest_addr[5],ifname,
        src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5]);
        return 1;
    }
    return -1;
}
/*End of send unity*/
/*begin of udp listen unity*/

int Wolcheck(unsigned char *packet, unsigned char *dest_addr)
{
    int offset = 0;
    unsigned char tmp[6];
    //check 0xff * 6
    for (int i = 0; i < 6; i++)
    {
        if (*(packet + offset) != 0xFF)
        {
            return -1;
        }
        offset++;
    }
    //get first mac addr
    for (int i = 0; i < 6; i++)
    {
        tmp[i] = *(packet + offset);
        offset++;
    }
    //check another 15 mac addr
    for (int i = 0; i < 15; i++)
    {
        for (int j = 0; j < 6; j++)
        {
            if (*(packet + offset) != tmp[j])
            {
                return -1;
            }
            offset++;
        }
    }
    memcpy(dest_addr, tmp, 6);
    return 1;
}
void CloseSocket(int signum)
{
    if (bind_sock>0)
    {
        close(bind_sock);
        exit(-1);
    }
}
int Listener(int port,char * ifname)
{

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    
    unsigned char recvbuf[1024] = {0};
    unsigned char dest[6] = {0};
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    int n;
    //udp socket
    if ((bind_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        clog_error(CLOG(CLI_ERROR),"Error in creating udp socket :%s",strerror(errno));
        return -1;
    }
    //bind
    if (bind(bind_sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        clog_error(CLOG(CLI_ERROR),"Error in bind udp port %d : %s",port,strerror(errno));
        return -1;
    }
    clog_info(CLOG(CLI_OUT),"Begin listen at udp port:%d",port);
    //handler
    signal(SIGINT, CloseSocket);
    while (1)
    {
        memset(recvbuf, 0, sizeof(recvbuf));
        n = recvfrom(bind_sock, recvbuf, sizeof(recvbuf), 0,
                     (struct sockaddr *)&peeraddr, &peerlen);
        if (n < 0)
        {

            if (errno == EINTR)
                continue;
            
            clog_error(CLOG(CLI_ERROR),"Error in receive : %s",strerror(errno));
        }
        else if (n > 0)
        {
            if (n == 102) //normal wol packet len
            {
                if (Wolcheck(recvbuf, dest) > 0)
                {
                    clog_set_level(CLI_OUT, CLOG_INFO);
                    clog_info(CLOG(CLI_OUT),"Receive wol packet to %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x from %s:%d",
                    dest[0], dest[1], dest[2], dest[3], dest[4], dest[5],
                    inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));
                    SendWol(dest,ifname);
                }
                else
                {
                    clog_warn(CLOG(CLI_OUT),"Invalid wol packet from %s:%d",inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));
                }
            }
            else
            {
                clog_warn(CLOG(CLI_OUT),"Drop packet from %s:%d,reason: not wol packet",inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));
            }
        }
    }
}
int RunTimeCheck(int port,char * ifname)
{
    unsigned char src_addr[14]={0};
    int sock;

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    clog_info(CLOG(CLI_OUT),"Checking the mac addr of interface:%s",ifname);
    if (Getifaddr(ifname,src_addr)<0)
    {
        clog_error(CLOG(CLI_ERROR),"Error in get the mac addr");
        return -1;
    }
    clog_info(CLOG(CLI_OUT),"%s's mac addr is %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x. ok",ifname,src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5]);
    clog_info(CLOG(CLI_OUT),"Checking the udp port : %d",port);
    //udp socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        clog_error(CLOG(CLI_ERROR),"Error in creating udp socket :%s",strerror(errno));
        return -1;
    }
    //bind
    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        clog_error(CLOG(CLI_ERROR),"Error in bind udp port %d : %s",port,strerror(errno));
        return -1;
    }
    clog_info(CLOG(CLI_OUT),"Udp port %d. ok",port);
    close(sock);
    sock = socket(PF_PACKET, SOCK_RAW, 0);
    clog_info(CLOG(CLI_OUT),"Checking send raw packet.");
    if (sock < 0)
    {
        if (errno == EPERM)
        {
            clog_error(CLOG(CLI_OUT),"Sending Ethernet frame needs root privilege");
        }
        else
        {
            clog_error(CLOG(CLI_ERROR),"Ethernet frame socket error : %s",strerror(errno));
        }
        return -1;
    }
    clog_info(CLOG(CLI_OUT),"Send raw packet success. ok");
    close(sock);
    return 1;
}
//start a daemon and log to path
int StartDeamon(char * logpath)
{
    pid_t pid;

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        exit(EXIT_FAILURE);

	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGHUP,SIG_IGN);

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);

    chdir("/");
    clog_free(CLI_OUT);
    clog_free(CLI_ERROR);
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }
    signal(SIGCHLD,SIG_IGN);
    CLI_ERROR=CLI_OUT;
    clog_init_path(CLI_OUT,logpath);
    return 0;
}
int main(int argc,char *argv[])
{
    int r,dae=1;
    char c;
    char * log = "/var/log/udp2ewol.log";
    char * ifname = "eth0";
    int port=9;
	while ((c = getopt(argc, argv, "hni:l:p:")) != -1)
		switch (c) {
		case 'i': ifname = optarg;	break;
		case 'l': log=optarg; break;
        case 'n': dae=0; break;
        case 'p': port=atoi(optarg); break;
    	case '?': 
        case 'h': printf("%s",usage_msg); exit(-1); break;

		}
    /* Initialize the logger */
    r = clog_init_fd(CLI_OUT, 1);
    if (r != 0) {
        fprintf(stderr, "Logger initialization failed.\n");
        return 1;
    }
    r = clog_init_fd(CLI_ERROR, 2);
    if (r != 0) {
        fprintf(stderr, "Logger initialization failed.\n");
        return 1;
    }
    clog_set_level(CLI_OUT, CLOG_INFO);
    clog_set_level(CLI_ERROR,CLOG_ERROR);
    clog_info(CLOG(CLI_OUT), "Initing udp2ewol");
    if (RunTimeCheck(port,ifname)>0)
    {
        clog_info(CLOG(CLI_OUT), "Init success.");
    }
    else
    {
        clog_error(CLOG(CLI_ERROR),"Init fail,exiting...");
        return -1;
    }
    if (dae)
    {
        clog_info(CLOG(CLI_OUT), "Start daemon...");
        StartDeamon(log);
    }
    Listener(port,ifname);
    return 0;
}