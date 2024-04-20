#include "connection.h"
#include "dns_stream.h"
#include "dns_cache.h" 

#define RESOLVER_ADDR "127.0.0.2"
#define PORTS 53


int main(int argc, const char * argv[]){
    if (argc != 3) {
        printf("USAGE: /.server SERVER-IP SERVER-HOSTFILE\n");
        exit(1);
    }

    const char * serverIP = argv[1];
    int serverPort = PORTS;
    const char * hostfile = argv[2];
    
    printf(">> Try Bind Server at %s@%d...\n", serverIP, serverPort);

    int sock = startTCPServer(serverIP, serverPort);
    struct sockaddr_in * clientAddr = newSocketaddr_t(0, 0);
    
    printf(">> Data Base Setup Start\n");
    DataBase* db = newdb(hostfile);
    print_db(db);
    
    printf(">> Data Base Setup Finished\n\n");
    printf(">> Server start at %s@%d...\n", serverIP, serverPort);
    
    while (1) {
        int receivedSocket = Accept(sock, clientAddr);
        
        Buffer * s = newBuffer();

        Dns_Packet * recvMesg = newPacket();
        int a = RecvTCP_Buffer(receivedSocket, s);
        printf("handle_in_packet return %d\n", a);
        handle_in_packet(recvMesg, s);
        
        print_message(recvMesg);
        int ret_code = FindIPfromLocal(recvMesg, db);
        
        printf("\n>> Resolve Result: %s\n", ret_code > 0 ? "Find Direct Answer" :
               (ret_code == 0 ? "Find Nextlevel NS Record" : "No Such Domain"));
        if (ret_code == -1) {
            recvMesg->headerrcode = rcode_NXDOMAIN;
        }
        recvMesg->headerQR = 1;
        print_message(recvMesg);
        
        SendTCP_Message(receivedSocket, recvMesg);
      
        freeBuffer(s);
       
        freeMessage(recvMesg);
        close(receivedSocket);
    }
    return 0;
}
