#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<strings.h>
#include<netinet/in.h>
#include<linux/if.h>
#include<netpacket/packet.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/select.h>
#include<time.h>
#include<string.h>
#include<signal.h>
#include"md5.h"

uint8_t p_hdr[60]={0x00},buf[512];
uint8_t dstmac[6]={0x01,0x80,0xc2,0x00,0x00,0x03};//802.1x的组地址
uint8_t localmac[6]={0x00};//本机的mac地址
struct sockaddr_ll toaddr;
int sockfd,stat=0;
extern u_char name[10],passwd[20];
u_char md5buf[30],digmd5buf[16];


/***********************************************************
获取本机的mac信息（mac地址和接口号）；
**************************************************************/
void getlocaleth() {
	struct ifreq ifr;
	int i;
	sockfd=socket(PF_PACKET,SOCK_RAW,htons(0x888e));
	bcopy("eth0",ifr.ifr_name,6);
	if(ioctl(sockfd,SIOCGIFHWADDR,&ifr)==-1) {
		perror("ioctl");
		exit(1);
	}
	bcopy(ifr.ifr_hwaddr.sa_data,localmac,6);
	puts("my local mac is:");
	for(i=0;i<6;i++) {
		printf("%02x",localmac[i]);
		if(i!=5)
			putchar(':');
	}
	putchar(10);
	putchar(10);
	puts("*****************************************************");
	if(ioctl(sockfd,SIOCGIFINDEX,&ifr)==-1) {
		perror("ioctl");
		exit(1);
	}
	bzero(&toaddr,sizeof(toaddr));
	toaddr.sll_ifindex=ifr.ifr_ifindex;
	toaddr.sll_family=PF_PACKET;
	close(sockfd);
}


/***********************************************************
构建eap-start数据包；
**************************************************************/
void build_startp() {
	bcopy(dstmac,p_hdr,6);
	bcopy(localmac,p_hdr+6,6);
	p_hdr[12]=0x88;
	p_hdr[13]=0x8e;
	p_hdr[14]=0x01;
	p_hdr[15]=0x01;
	p_hdr[16]=p_hdr[17]=0x00;
}


/***********************************************************
发送eap-start数据包；
**************************************************************/
void send_startp() {
	if((sockfd=socket(PF_PACKET,SOCK_RAW,htons(0x888e)))<0) {
	perror("socket");
	exit(1);
	}
	build_startp();
	if(sendto(sockfd,p_hdr,18,0,(struct sockaddr *)&toaddr,sizeof(toaddr))<0) {
		perror("starting wrong\n");
		exit(1);
	}
}

/***********************************************************
构建identity数据包用来上传用户名；
**************************************************************/
void build_namep() {
	build_startp();
	p_hdr[15]=p_hdr[16]=p_hdr[20]=0x00;
	p_hdr[17]=0x0e;
	p_hdr[18]=0x02;
	p_hdr[19]=buf[19];
	p_hdr[21]=0x0e;
	p_hdr[22]=0x01;
	bcopy(name,p_hdr+23,strlen(name));
	
}

/***********************************************************
构建用来上传用户密码的数据包；
**************************************************************/
void build_passwdp() {
	build_namep();
	p_hdr[19]=buf[19];
	p_hdr[17]=p_hdr[21]=0x1f;
	p_hdr[22]=0x04;
	p_hdr[23]=0x10;
        md5buf[0]=buf[19];
	bcopy(passwd,md5buf+1,strlen(passwd));
	bcopy(&buf[24],md5buf+strlen(passwd)+1,16);
	MD5_CTX md5; // 						MD5
    	MD5Init(&md5);//            					加密    
    	MD5Update(&md5,md5buf,strlen((char *)md5buf));  //		过程	
    	MD5Final(&md5,digmd5buf);//			对通信ID+passwd+attach-key 字符窜进行16位的hash运算
	memcpy(p_hdr+24,digmd5buf,16);
	}

/***********************************************************
开始发送服务器要求的数据包；
**************************************************************/
void startup() {
	if(recvfrom(sockfd,buf,512,0,NULL,NULL)<0) {
		perror("recvfrom");
		exit(1);
	}
	if(buf[18]==0x03&&(bcmp(buf,localmac,6)==0)) {
		puts("#################################################");
		puts("conncet succeed");
		puts("#################################################");
		stat=1;
	}
	else if(buf[18]==0x04&&(bcmp(buf,localmac,6)==0)) {
		puts("connect failue");
		puts(&buf[24]);
		exit(1);
	}
	if((bcmp(buf,localmac,6)==0)&&buf[22]==1) {
		build_namep();
		if(sendto(sockfd,p_hdr,32,0,(struct sockaddr *)&toaddr,sizeof(toaddr))<0) {
			if(stat==0) {
				perror("upload name wrong\n");
				exit(1);
			}
			else if(stat==1) sig_inter(stat);
		}
		putchar(10);
		putchar(10);
		puts("*****************************************************");
		puts("upload name succeed");
	}

	if((bcmp(buf,localmac,6)==0)&&buf[22]==4) {
		build_passwdp();
		if(sendto(sockfd,p_hdr,40,0,(struct sockaddr *)&toaddr,sizeof(toaddr))<0) {
			perror("upload passwd wrong\n");
			exit(1);
		}
		putchar(10);
		putchar(10);
		puts("*****************************************************");
		puts("upload passwd succeed");
	}
}


/***********************************************************
开始上传信息并对socket监听；
**************************************************************/
void upinfo() {
	fd_set set;
	FD_ZERO(&set);
	FD_SET(sockfd,&set);
	struct timeval timeout;
	timeout.tv_sec=75;//设置75秒超时
	timeout.tv_usec=0;
	while(1) {
		switch(select(sockfd+1,&set,NULL,NULL,&timeout)) {
			case 1:
				startup();
				break;
			case 0:
				puts("timeout");break;
			case -1:
			default:
				perror("selcet");
				if(stat==1) sig_inter(stat);
		}
		timeout.tv_sec=75;
		timeout.tv_usec=0;
	}
}


/***********************************************************
信号处理函数；
**************************************************************/
void sig_inter(int signo) {
	build_startp();
	p_hdr[15]=0x02;
	if(sendto(sockfd,p_hdr,18,0,(struct sockaddr *)&toaddr,sizeof(toaddr))<0) {
		perror("logoff wrong\n");
		exit(1);
	}
	puts("logoff succeed");
	exit(0);
}


