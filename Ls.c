#include "connection.h"
#include "dns_stream.h"
#include "dns_cache.h"

#define CACHE_FILE "cache-resolver.txt"
#define CLIENT_ADDR "127.0.0.1"
#define CLIENT_PORT 53

void start(const char* LocalserverIP, const int LocalserverPort, const char* rootServerIP, const int rootServerPort, const char* cachePath)
{
    DataBase* db = newdb(cachePath);

    int sockfd = startUDPServer(LocalserverIP, LocalserverPort);

    
    printf("\n$ Local DNS Server on %s@%d...\n\n\n", LocalserverIP, LocalserverPort);

    while (1) {
        Dns_Packet* clientQueryPacket = newPacket();
        Buffer* s = newBuffer();
        // RecvTCP_Buffer(receivedSocket, s);
        struct sockaddr_in* cliaddr = SetNewSocketAddr(CLIENT_ADDR, CLIENT_PORT);
        RecvUDP_Buffer(sockfd, s, cliaddr);
        printf("> ** Accepted Client from %s@%d **\n\n", inet_ntoa(cliaddr->sin_addr), ntohs(cliaddr->sin_port));
        struct timeval start, stop;
        double secs = 0;
        gettimeofday(&start, NULL);
        handle_in_packet(clientQueryPacket, s);

        Question* q = clientQueryPacket->questions;
        printf(">> Accepted Message:\n");
        print_message(clientQueryPacket);

        Dns_Packet* possibleAnswerMessage = newPacket();
        add_question_query_r(possibleAnswerMessage, q->QType, q->QName);
        printf("> Start Query\n");

        int ret_code = FindIPfromLocal(possibleAnswerMessage, db);
        if (ret_code > 0) {
            printf("<< Find Record in Local DNS Cache\n\n");
            print_message(possibleAnswerMessage);
            Buffer* s = newBuffer();
            handle_out_packet(s, possibleAnswerMessage);
            SendUDP_Buffer(sockfd, s, cliaddr);
            freeBuffer(s);
            freeMessage(possibleAnswerMessage);
            printf("\n< Client Service End \n\n");
            continue;
        }
        int maxloop = 20;
        struct sockaddr_in* nextServerAddr = SetNewSocketAddr(rootServerIP, rootServerPort);
        printf("> Visit Root Server %s@%d\n", inet_ntoa(nextServerAddr->sin_addr), ntohs(nextServerAddr->sin_port));
        do {
            int serverSock = Socket(true);
            Connect(serverSock, nextServerAddr);
            Buffer* s = newBuffer();
            put2Bytes(s, 0);
            handle_out_packet(s, clientQueryPacket);
            SendTCP_Buffer(serverSock, s);
            freeBuffer(s);
            printf("> Waiting Server Response %s@%d ...\n", inet_ntoa(nextServerAddr->sin_addr), ntohs(nextServerAddr->sin_port));
            possibleAnswerMessage = RecvTCP_Message(serverSock);
            close(serverSock);
            if (possibleAnswerMessage->answerNum != 0) {
                trace_message(possibleAnswerMessage);
                for (int i = 0; i < possibleAnswerMessage->answerNum; i++) {
                    RR* r = possibleAnswerMessage->answers + i;
                    if (search_db_identical_record_fromindex(db, 0, r) == -1) {
                        DNS_Record* dbr = addrecord_db_t(db, r);
                        printf("Cached record: ");
                        print_cache_record(dbr);
                    }
                }
                if (possibleAnswerMessage->questions[0].QType == DNS_RECORD_TYPE_MX) {
                    for (int i = 0; i < possibleAnswerMessage->additionalNum; i++) {
                        RR* r = possibleAnswerMessage->additionals + i;

                        if (search_db_identical_record_fromindex(db, 0, r) == -1) {
                            DNS_Record* dbr = addrecord_db_t(db, r);
                            printf("Cached record: ");
                            print_cache_record(dbr);
                        }
                    }
                }

                printf("Updated Cache DB\n");
                print_db(db);

                FILE* fd = fopen(CACHE_FILE, "w+");
                if (!fd) {
                    perror("Resolver Cache file open error");
                    break;
                } else {
                    savedb(db, fd);
                    fclose(fd);
                    printf("Successfully saved resolver cache\n");
                }

                break;
            }

            if (possibleAnswerMessage->headerrcode == rcode_NXDOMAIN) {
                printf("! Server Return: No such domain\n");
                break;
            }

            if (possibleAnswerMessage->authorityNum != 0) {
                trace_message(possibleAnswerMessage);
                RR* r = possibleAnswerMessage->authorities;

                nextServerAddr = newSocketaddr_t(ntohl(r->rdata.a_record.addr), PORTS);
                struct sockaddr_in addr;
                addr.sin_addr.s_addr = r->rdata.a_record.addr;
                printf("> Visit Next Server %s@%d\n", inet_ntoa(addr.sin_addr), ntohs(nextServerAddr->sin_port));
                continue;
            }

            printf("Encountered Error in resolver!\n");
            possibleAnswerMessage->headerrcode = rcode_server_fail;
            break;

        } while (possibleAnswerMessage->answerNum == 0 && maxloop--);

        printf("<< Ready to send back \n");
        print_message(possibleAnswerMessage);

        
        Buffer* t = newBuffer();
        handle_out_packet(t, possibleAnswerMessage);
        
        SendUDP_Buffer(sockfd, t, cliaddr);
        freeBuffer(t);
        gettimeofday(&stop, NULL);
        secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);
        printf("\n< ** Client Service End **\nRequest finished in %f ms\n", secs * 1000);

        time_t current_time = time(NULL);
        char* c_time_string = ctime(&current_time);
        (void)printf("Current Time: %s\n", c_time_string);
        freeMessage(possibleAnswerMessage);
        
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 3) {
        printf("USAGE: ./resolver LocalDNS-bind-IP  HostFile\n");
        exit(1);
    }

    start(argv[1], PORTS, ROOTSERVER_ADDR, PORTS, argv[2]);

    return 0;
}