

#ifndef dns_cache_h
#define dns_cache_h

#include "connection.h"
#include "dns.h"
#include "dns_stream.h"

#define MAX_RECORD 32

struct DNS_Record {
    char * name; 
    char * original_name;
    uint32_t ttl;
    DNSClass_t class;
    DNSType_t  type;
    char * record;
    Rdata data;    
};

struct DataBase {

    struct DNS_Record records[MAX_RECORD];
    int len;
};

typedef struct DNS_Record DNS_Record;

typedef struct DataBase DataBase;



void add_resource(RR * mr, DNS_Record * r);

void add_answer(Dns_Packet * msg, DNS_Record * r);

void add_authority(Dns_Packet * msg, DNS_Record * r);

void add_additional(Dns_Packet * msg, DNS_Record * r);



void initdb(DataBase * db, FILE * fs);

DataBase * newdb(const char * fname);

void savedb(DataBase * db, FILE * fs);

void addrecord_db(DataBase * db, const char * name, uint32_t ttl, DNSClass_t class, DNSType_t type, const char * record);

DNS_Record * addrecord_db_t(DataBase * db, RR * record);


int search_db(DataBase * db, Question * q);

int search_db_r(DataBase * db, RR * r);

int Compare_with_db(DataBase * db, int start, Question * q);

int search_db_indirect_fromindex(DataBase * db, int start, Question * q);

void cacheDBRecord_if_not_found(DataBase * db, RR * r);

int search_db_identical_record_fromindex(DataBase *db, int start, RR * r);


int getTypeIntValue(char * str, const char ** set, int setsize);

void print_cache_record(DNS_Record * r);

void print_db(DataBase * db);


int FindIPfromLocal(Dns_Packet * mesg, DataBase * cacheDB);

#endif /* dns_h */
