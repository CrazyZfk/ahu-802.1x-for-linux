#include<stdio.h>
#include<stdlib.h>
#include<errno.h>

/************************************
主要的认证过程
*************************************/

int start_ath() {
	getlocaleth();//获取mac信息
	send_startp();//开始认证
	upinfo();//上传信息
}

