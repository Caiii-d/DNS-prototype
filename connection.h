#ifndef connection_h
#define connection_h

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <utime.h>
#include <time.h>


static const char * DNS_TYPE_SET [] = { "", "A", "NS", "", "", "CNAME", "", "", "", "", "", "", "", "", "", "MX"}; 
static const char * DNS_CLASS_SET [] = { "", "IN" };


#define HEADER_FLAG_QR_ISQUERY   	 0
#define HEADER_FLAG_QR_ISRESPONSE	 1


#define HEADER_FLAG_OPCODE_STANDARDQUERY	 0
#define HEADER_FLAG_OPCODE_INVQUERY	 1
#define HEADER_FLAG_OPCODE_STATUS	 2
typedef int opcode_t;

#define DNS_RECORD_TYPE_A      	 1
#define DNS_RECORD_TYPE_NS     	 2
#define DNS_RECORD_TYPE_CNAME  	 5
#define DNS_RECORD_TYPE_PTR    	12
#define DNS_RECORD_TYPE_MX     	15
typedef int DNSType_t;

#define DNS_CLASS_TYPE_IN	 1
typedef int DNSClass_t;

static const char * RCODE_SET [] = { "NO ERROR", "FORMAT ERROR", "SERVER FAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };

typedef enum {
    rcode_good = 0,
    rcode_format_error = 1,
    rcode_server_fail = 2,
    rcode_NXDOMAIN = 3,
    rcode_query_not_support = 4,
    rcode_policy_refused = 5
} rcode_t;

void initSockaddr(struct sockaddr_in * addr, const char * name, int port);
void initSockaddr_t(struct sockaddr_in * addr, in_addr_t rawIP, int port);
struct sockaddr_in * SetNewSocketAddr(const char * name, int port);
struct sockaddr_in * newSocketaddr_t(in_addr_t rawIP, int port);



int startTCPServer(const char * tcpServerIP, int port);
int startUDPServer(const char * udpServerIP, int port);
int startTCPClient(const char * tcpServerIP, int port);
int startUDPClient(const char * udpServerIP, int port, struct sockaddr_in ** ret_addr);
int startUDPClient_r(in_addr_t rawUDPServerIP, int port, struct sockaddr_in ** ret_addr);
int startUDPClient_o(struct sockaddr_in * addr);


int     Socket(int isTCP);
void    Connect(int sock, struct sockaddr_in * addr);
ssize_t SendTCP(int sock, const char * buf, ssize_t len);
ssize_t RecvTCP(int sock, char * buf, ssize_t len);
ssize_t SendUDP(int sock, const char * buf, ssize_t len, struct sockaddr_in * addr);
ssize_t RecvUDP(int sock, char * buf, ssize_t len, struct sockaddr_in * addr);
void    Listen(int sock);
void    Bind(int sock, struct sockaddr_in * addr);
int     Accept(int listen_sock, struct sockaddr_in * addr);



#endif
