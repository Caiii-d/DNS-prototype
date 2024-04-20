

#ifndef dns_h
#define dns_h

#include "connection.h"

#ifdef DEBUG
    #define PORTS 5300
#else
    #define PORTS 53
#endif

#define RESOLVER_ADDR "127.0.0.2"
#define ROOTSERVER_ADDR "127.0.0.3"

union Rdata {
    struct { char *   name; }     name_record;
    struct { in_addr_t addr;}     a_record;
    struct { uint16_t preference; char *exchange; } mx_record;
};

//RR format
struct RR {
    char *name;
    unsigned short rtype;
    unsigned short rclass;
    unsigned int rttl;
    unsigned short rdlength;
    union Rdata rdata;
};

//question part
struct Question {
    char *   QName;
    unsigned short QType;
    unsigned short QClass;
};

//hearer
struct Header {
    unsigned short headerID;
    bool headerQR;
    unsigned short headerOpcode;
    bool headerAA;
    bool headerTC;
    bool headerRD;
    bool headerRA;
    unsigned short headerz;
    unsigned short headerrcode;
    
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorityNum;
    unsigned short additionalNum;
};



//DNS报文
struct Dns_Packet {
    unsigned short headerID;
    bool headerQR;
    unsigned short headerOpcode;
    bool headerAA;
    bool headerTC;
    bool headerRD;
    bool headerRA;
    unsigned short headerz;
    unsigned short headerrcode;
    
    unsigned short queryNum; 
    unsigned short answerNum; 
    unsigned short authorityNum; 
    unsigned short additionalNum; 
    
    struct Question questions[16];
    struct RR answers[16];
    struct RR authorities[16];
    struct RR additionals[16];
    
};

typedef struct Question Question;
typedef union Rdata Rdata;
typedef struct RR RR;
typedef struct Dns_Packet Dns_Packet;
typedef struct Header Header;

//translate the domain name
char * format_ip(char * normal_url);
char * str2url(const char * str);
char * url2str(const char * url);
int getEnumValueFromSet(const char * str, const char ** set, int setsize);


void print_message(Dns_Packet * message);
void trace_message(Dns_Packet * message);
void initMessage(Dns_Packet * message);
void freeMessage(Dns_Packet * message);
Dns_Packet * newPacket(void);
//build the filed in the DNS
void make_header_query(Dns_Packet * mesg, int recursive_desired, int numQuestions);
int  make_question_query(Question * q, const char * type, const char * name );
int  make_question_query_r(Question * q, DNSType_t type, const char * zippedname );
void add_question_query(Dns_Packet * mesg, const char * type, const char * name);
void add_question_query_r(Dns_Packet * mesg, DNSType_t type, const char * name_alloced );



#endif /* dns_h */

