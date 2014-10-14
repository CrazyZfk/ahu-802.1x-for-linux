#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<signal.h>
#include<termios.h>

u_char name[15],passwd[30];
void sig_inter(int);

int main(int argc,char *argv[]) {
	char c;
	int i=0;
	struct termios initialsetting,newsetting;

	tcgetattr(fileno(stdin),&initialsetting);
	puts("name");
	while((c=getchar())!='\n') {
		name[i++]=c;
	}


	newsetting=initialsetting;
	newsetting.c_lflag &=~ECHO;
	if(tcsetattr(fileno(stdin),TCSAFLUSH,&newsetting)!=0) {
		perror("tcsetattr");
		exit(1);
	}


	i=0;
	puts("password");
	while((c=getchar())!='\n') {
		passwd[i++]=c;
	}
	if(tcsetattr(fileno(stdin),TCSAFLUSH,&initialsetting)!=0) {
		perror("tcsetattr");
		exit(1);
	}

	signal(SIGINT,sig_inter);
	start_ath();
	exit(0);	
}

