/* Basic HTTP/Web honeypot for embedded systems (openwrt, mobiles, ...)
Copyright (C) Kost. Distributed under GPL.  */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#define BUFSIZE 8096

#define DEFAULTSERVER "Apache"
#define DEFAULTUSER "nobody"
#define MAXLOGRECSIZE BUFSIZE*2+1

char *pserver=DEFAULTSERVER;
char *logfile="nanoweblog.log";
char *dropuser=DEFAULTUSER;

int logtimeanddate=1;
int logtosyslog=1; /* log to syslog */
int logrequest=1; /* log complete request as it is to separate log*/

FILE *fptolog;

/* Returns the current local date and time in timenow. 
 * Here you can modify the output format
 * (default is yyyy-mm-dd hh:mm:ss) */
void whatistime(char *timenow, size_t max)
{
	struct tm *curtime;
	time_t cartime;

	time(&cartime);
	curtime = localtime(&cartime);
	if (logtimeanddate) {
		snprintf(timenow, max, "%04d-%02d-%02d %02d:%02d:%02d", curtime->tm_year + 1900
		 ,curtime->tm_mon + 1, curtime->tm_mday, curtime->tm_hour
			,curtime->tm_min, curtime->tm_sec);
	}

}

/* log contents from fmt to log file */
char repeatbuf[MAXLOGRECSIZE];	/* buffer to compare */
int repeatcount = 0;		/* Counter for 'message repeated x times' */
void logprintf(int dotime, char *fmt,...)
{
	va_list va;
	char buf[MAXLOGRECSIZE], buf2[MAXLOGRECSIZE];

	va_start(va, fmt);
	vsnprintf(buf, MAXLOGRECSIZE, fmt, va);
	va_end(va);

	if (strcmp(buf, repeatbuf) == 0) {
		repeatcount++;
		return;
	}

	if (repeatcount > 0) {
		if (logtimeanddate > 0) {
			whatistime(buf2, MAXLOGRECSIZE);
			fprintf(fptolog, "%s Last message repeated %d time(s)\n", buf2, repeatcount);
		} else
			fprintf(fptolog, "Last message repeated %d time(s)\n", repeatcount);
		repeatcount = 0;
		memset(repeatbuf, 0, sizeof(repeatbuf));
	}
	memcpy(repeatbuf, buf, sizeof(buf));

	if (dotime && logtimeanddate > 0) {
		whatistime(buf2, MAXLOGRECSIZE);
		fprintf(fptolog, "%s %s", buf2, buf);
	} else
		fprintf(fptolog, "%s", buf);
}

/* log to syslog using common format */
void syslogprintf(char *fmt,...)
{
	va_list va;
	char buf[MAXLOGRECSIZE];

	if (logtosyslog != 0) {
		va_start(va, fmt);
		vsnprintf(buf, MAXLOGRECSIZE, fmt, va);
		va_end(va);

#ifdef HAVE_OPENLOG
		openlog("nanoweblog", LOG_CONS, LOG_USER);
		syslog(LOG_WARNING, "%s", buf);
		closelog();
#else
#warning "Can't find usable syslog, disabled!"
		logprintf(1,"%s",buf);
#endif

	}
}

/* If we are running as root (EUID = 0),
 * drop root privileges and become USER. */
void dropprivileges(const char *user)
{
#ifdef HAVE_PWD_H
	struct passwd *entry;
	static int done = 0;

	/* Nothing to do if we are not root */
	if (done || geteuid() != 0) {
		done = 1;
		return;
	}
	/* Become user */
	entry = getpwnam(user);
	if (entry == NULL) {
		syslogprintf("Warning: user %s not found, "
			"running as root!!\n", user);
		return;
	}
	if (setgid(entry->pw_gid) == -1)
		perror("setgid()");
	if (setuid(entry->pw_uid) == -1)
		perror("setuid()");
	done = 1;
#else
#warning Ignoring drop priviledges!
#endif
}

int httpstdresponse (int fd, char *buffer, int httpcode, char *httpmsg, char *ctype, char *body) {
	(void)snprintf(buffer,BUFSIZE,"HTTP/1.1 %d %s\nServer: %s\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n%s", 
		httpcode, httpmsg, pserver, strlen(body), ctype, body); 
	(void)write(fd,buffer,strlen(buffer));
	return 1;
}

/* this is a child web server process, so we can exit on errors */
void web(int fd, char *ip)
{
	int responded=0;
	long i, ret, skipup=0;
	static char buffer[BUFSIZE+1]; /* static so zero filled */

	ret =read(fd,buffer,BUFSIZE); 	/* read Web request in one go */
	if(ret == 0 || ret == -1) {	/* read failure stop now */
		syslogprintf("Unable to read client request at fd %d", fd);
	}
	if(ret > 0 && ret < BUFSIZE)	/* return code is valid chars */
		buffer[ret]=0;		/* terminate the buffer */
	else buffer[0]=0;
	
	if (logrequest) {
		logprintf(1,"== request from %s: %s",ip, buffer);
	}

	for(i=0;i<ret;i++) {	/* remove CF and LF characters */
		if (skipup==0) buffer[i]=toupper(buffer[i]);
		if(buffer[i] == '\r' || buffer[i] == '\n') {
			buffer[i]='*';
			skipup=1;
		}
	}

	syslogprintf("== request from %s: %s", ip, buffer);

	/* For sake of Simpleness, return same for HEAD & GET, feel free to adapt */
	if( !strncmp(&buffer[0],"GET / ",6) || !strncmp(&buffer[0],"HEAD / ",7) ) {
		responded=httpstdresponse (fd, buffer, 200, "OK", "text/html", "<HTML>OK</HTML>");
	}

	if( !strncmp(&buffer[0],"GET /FAVICON.ICO ",17) || !strncmp(&buffer[0],"HEAD /FAVICON.ICO ",18) ) {
		responded=httpstdresponse (fd, buffer, 404, "NOT FOUND", "text/html", "<HTML>NOT FOUND</HTML>");
	} 

	if( !strncmp(&buffer[0],"GET /ROBOTS.TXT ",16) || !strncmp(&buffer[0],"HEAD /ROBOTS.TXT ",17) ) {
		responded=httpstdresponse (fd, buffer, 200, "OK", "text/plain", "User-agent: *\nDisallow: /");
	}

	if (!responded) { /* if not already handled request, fallback to default */
		unsigned int iseed = (unsigned int)time(NULL);
		srand (iseed);
		unsigned int fun = rand() % 10; /* give random responses just for fun */
		switch (fun) {
			case 0:
			httpstdresponse (fd, buffer, 200, "Processing", "text/html", "<HTML>Processing</HTML>");
			break;

			case 1:
			httpstdresponse (fd, buffer, 500, "Server Error", "text/html", "<HTML>Server Error</HTML>");
			break;

			case 2:
			httpstdresponse (fd, buffer, 403, "Forbidden", "text/html", "<HTML>Forbidden</HTML>");
			break;
			
			default:
			httpstdresponse (fd, buffer, 200, "OK", "text/html", "<HTML>OK</HTML>");
		}
		responded=1;
	}	
		
	sleep(1);	/* allow socket to drain before signalling the socket is closed */
	close(fd);
	exit(1);
}

/* main program */
int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;
	socklen_t length;
	static struct sockaddr_in cli_addr; /* static = initialised to zeros */
	static struct sockaddr_in serv_addr; /* static = initialised to zeros */

	if( argc < 2  || !strcmp(argv[1], "-?") || !strcmp(argv[1],"--help")) {
		(void)printf("Usage: %s <port-number> [droptouser] [logwholerequest] [logfile] [http-server-header]\n",argv[0]);
		(void)printf("Simple Example: %s 80\n",argv[0]);
		(void)printf(" - defaults to drop to user %s, log whole request to %s with server header %s\n",dropuser,logfile,pserver);
		(void)printf("Complex Example: %s 80 nobody 1 /var/log/nanoweblog.log \"Microsoft IIS/6.0\"\n",argv[0]);
		exit(0);
	}
	if(fork() != 0) /* Become deamon + unstopable and no zombies children (= no wait()) */
		return 0; /* parent returns OK to shell */
	(void)signal(SIGCHLD, SIG_IGN); /* ignore child death */
	(void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
	for(i=0;i<32;i++) (void)close(i); /* close open files */
	(void)setpgrp();		/* break away from process group */
	port = atoi(argv[1]);
	if (argc > 2) dropuser=argv[2];
	if (argc > 3) logrequest=atoi(argv[3]);
	if (argc > 4) logfile=argv[4];
	if (argc > 5) pserver=argv[5];
	syslogprintf("nanoweblog started - port %d using PID %d dropping to %s with log file %s", port ,getpid(),dropuser,logfile);
	/* setup logging file */
	fptolog=fopen(logfile,"a");
	if (fptolog==NULL) {
		syslogprintf("error opening log file: %s", logfile);
		exit(1);
	}
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0) {
		syslogprintf("Error executing system call socket(): %d", errno);
		exit(3);
	}
	if(port < 0 || port >65535) {
		syslogprintf("Error - invalid port number specified (1-65535): %s",argv[1]);
		exit(3);
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0) {
		syslogprintf("Error executing system call bind(): %d", errno);
		exit(3);
	}
	if( listen(listenfd,64) <0) {
		syslogprintf("Error executing system call listen(): %d", errno);
		exit(3);
	}
	dropprivileges(dropuser);
	for(;;) {
		char *ipaddr;
		length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0) {
			syslogprintf("Error executing system call accept() - SYN SCAN?: %d", errno);
			continue;
		}
		ipaddr = inet_ntoa(cli_addr.sin_addr);
		if((pid = fork()) < 0) {
			syslogprintf("Error executing system call fork(): %d", errno);
			exit(3);
		}
		else {
			if(pid == 0) { 	/* child */
				(void)close(listenfd);
				web(socketfd,ipaddr); /* never returns */
			} else { 	/* parent */
				(void)close(socketfd);
			}
		}
	}
}
