#include "connection.h"
#include "dns_stream.h"
#include "dns_cache.h"
#include <sys/time.h>

#define LOCALDNSSERVER "127.0.0.2"


char* qType;
char* qname;
char* localserverIP = LOCALDNSSERVER;
int localserverPort = PORTS;

int main(int argc, const char* argv[])
{
    
    if (argc != 3) {
        printf("USAGE: %s query-type query-url\n", argv[0]);
        exit(1);
    }

   
    qType = (char*)argv[1];
    qname = (char*)argv[2];

  
    struct timeval start, stop;
    gettimeofday(&start, NULL);

    
    Dns_Packet* sendMesg = newPacket();
    add_question_query(sendMesg, qType, qname);

    
    print_message(sendMesg);

    
    struct sockaddr_in* addr = SetNewSocketAddr(localserverIP, localserverPort);
    int sock = startUDPClient_o(addr);

    SendUDP_Message(sock, sendMesg, addr);

    
    Dns_Packet* recvMesg = RecvUDP_Message(sock, addr);
    print_message(recvMesg);

   
    gettimeofday(&stop, NULL);
    double secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);

    printf("Request Time Taken: %f ms\n", secs * 1000);

    time_t current_time = time(NULL);
    char* c_time_string = ctime(&current_time);
    printf("Current Time: %s\n", c_time_string);

    return 0;
}
