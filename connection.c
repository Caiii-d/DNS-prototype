#include "connection.h"

void initSockaddr(struct sockaddr_in * addr, const char * name, int port){
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, name, &addr->sin_addr.s_addr);
}


void initSockaddr_t(struct sockaddr_in * addr, in_addr_t rawIP, int port){
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_addr.s_addr = htonl(rawIP);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
}


struct sockaddr_in * SetNewSocketAddr(const char * name, int port){
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, name, &addr->sin_addr.s_addr);
    return addr;
}

struct sockaddr_in * newSocketaddr_t(in_addr_t rawIP, int port){
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_addr.s_addr = htonl(rawIP);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    return addr;
}



void Bind(int sock, struct sockaddr_in * addr){
    if (bind(sock, (const struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Bind() failed"); exit(1);
    }
}

void Listen(int sock){
    if (listen(sock, 100) < 0) {
        perror("Listen() failed"); exit(1);
    }
}

int Accept(int sockfd, struct sockaddr_in * addr){
    socklen_t t = sizeof(struct sockaddr_in);
    int accpeted_socket = accept(sockfd, (struct sockaddr *) addr, &t);
    if (accpeted_socket < 0) {
        perror("Accept() failed");
    }
    return accpeted_socket;
}



int Socket(int isTCP){
    int sockfd = socket(PF_INET, isTCP ? SOCK_STREAM : SOCK_DGRAM, isTCP ? IPPROTO_TCP : IPPROTO_UDP);
    if (sockfd < 0) {
        fprintf(stderr, "Socket error"); exit(1);
    }
    return sockfd;
}

void Connect(int sock, struct sockaddr_in * addr){
    if (connect(sock, (const struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Connect() failed"); exit(1);
    }
}

ssize_t SendTCP(int sock, const char * buf, ssize_t len){
    return send(sock, (void *)buf, len, 0);
}

ssize_t RecvTCP(int sock, char * buf, ssize_t len){
    return recv(sock, (void *) buf, len, 0);
}

ssize_t SendUDP(int sock, const char * buf, ssize_t len, struct sockaddr_in * addr){
    return sendto(sock, (void *)buf, len, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
}

ssize_t RecvUDP(int sock, char * buf, ssize_t len, struct sockaddr_in * addr){
    socklen_t t = sizeof(struct sockaddr_in);
    return recvfrom(sock, (void *)buf, len, 0, (struct sockaddr *)addr, &t);
}



int startTCPServer(const char * tcpServerIP, int port)
{
    int sock = Socket(true);

    struct sockaddr_in * addr = SetNewSocketAddr(tcpServerIP, port);
    
    if (bind(sock, (const struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Bind() failed"); exit(1);
    }
    
    if (listen(sock, 100) < 0) {
        perror("Listen() failed"); exit(1);
    }

    return sock;
}

int startUDPServer(const char * udpServerIP, int port)
{
    int sock = Socket(false);
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, udpServerIP, &addr->sin_addr.s_addr);

    if (bind(sock, (const struct sockaddr *) addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Bind() failed"); exit(1);
    }
    return sock;
}

int startTCPClient(const char * tcpServerIP, int port)
{
    int sock = Socket(true);
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    Connect(sock, addr);
    printf("Connect to Local DNS Server %s@%d...\n", tcpServerIP, port);
    return sock;
}

int startUDPClient(const char * udpServerIP, int port, struct sockaddr_in ** ret_addr)
{
    int sock = Socket(false);
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, udpServerIP, &addr->sin_addr.s_addr);

    *ret_addr = addr;
    return sock;
}

int startUDPClient_r(in_addr_t rawUDPServerIP, int port, struct sockaddr_in ** ret_addr)
{
    int sock = Socket(false);
    struct sockaddr_in * addr = calloc(1, sizeof(struct sockaddr_in));
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_addr.s_addr = htonl(rawUDPServerIP);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    *ret_addr = addr;
    return sock;
}

int startUDPClient_o(struct sockaddr_in * addr)
{
    int sockfd = Socket(false);
    return sockfd;
}
