

#ifndef dns_stream_h
#define dns_stream_h

#include "connection.h"
#include "dns.h"

struct Buffer {
    char buffer[4096];
    int content_len;
    int cursor_pos;
};

typedef struct Buffer Buffer;

void initBuffer(Buffer * s);

Buffer * newBuffer(void);
void freeBuffer(Buffer * s);



int cout(Buffer * des, char * src, size_t size);
int put1Byte(Buffer * des, uint8_t src);
int put2Bytes(Buffer * des, uint16_t src);
int put4Bytes(Buffer * des, uint32_t src);

int Buffer_read(char * des, Buffer * src, size_t size);
uint8_t read_8bit_from_buffer(Buffer * src);
uint16_t read_16bit_from_buffer(Buffer * src);
uint32_t read_32bit_from_buffer(Buffer * src);

//Writer Functions

void handle_in_packet(Dns_Packet * mesg, Buffer * s);
void handle_in_Header(Header * head, Buffer * s);
void handle_in_Question(Question * q, Buffer *s);
void handle_in_RR(RR * r, Buffer * s);
void handle_in_RData(RR * r, Buffer * s);

int  getURLString(char * des, Buffer * src);

char * getURLString_allocated(Buffer * src);

//Reader Functions 

ssize_t SendTCP_Buffer(int sock, Buffer * buf);
ssize_t RecvTCP_Buffer(int sock, Buffer * buf);
ssize_t SendUDP_Buffer(int sock, Buffer * buf, struct sockaddr_in * addr);
ssize_t RecvUDP_Buffer(int sock, Buffer * buf, struct sockaddr_in * addr);

void handle_out_packet(Buffer * s, Dns_Packet * mesg);
void handle_out_Header(Buffer * s, Header * head);
void handle_out_Question(Buffer * s, Question * q);
void handle_out_RR(Buffer * s, RR * r);
void handle_out_RData(Buffer * s, RR * r);
void cout_TCP_Header(Buffer * s);

int  putURLString(Buffer * des, char * src);



void 	  SendTCP_Message(int sock, Dns_Packet * mesg);
Dns_Packet * RecvTCP_Message(int sock);
void 	  SendUDP_Message(int sock, Dns_Packet * mesg, struct sockaddr_in * serverAddr);
Dns_Packet * RecvUDP_Message(int sock, struct sockaddr_in ** ret_clientAddr);





#endif /* dns_stream_h */
