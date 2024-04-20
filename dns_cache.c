#include "dns_cache.h"

int getTypeIntValue(char * str, const char ** set, int setsize){
    for (int i = 1; i < setsize; i++) {
        if (strcmp(str, set[i]) == 0) {
            return i;
        }
    }
    fprintf(stderr, "cache_parse(): no such value : %s\n", str);
    return -1;
}

void print_cache_record(DNS_Record * r){
    char * p = url2str(r->name);
    printf("Record: %s %d %s %s %s\n", p, r->ttl, DNS_CLASS_SET[r->class], DNS_TYPE_SET[r->type], r->record);
    free(p);
};

void print_db(DataBase * db){
    for (int i = 0; i < db->len; i++) {
        print_cache_record(db->records + i);
    }
};

char * getFormatedURLFromNormalURL(char * normal_url){
    Buffer s; initBuffer(&s);
    char * url = strdup(normal_url);
    char * tok = strtok(url, ".");
    uint8_t len = 0;
    while (tok) {
        len = (uint8_t) strlen(tok);
        put1Byte(&s, len);
        cout(&s, tok, len);
        tok = strtok(NULL, ".");
    }
    len = 0;
    put1Byte(&s, len);
    free(url);
    char * ret = strdup(s.buffer);
    return ret;
}


int FindIPfromLocal(Dns_Packet * mesg, DataBase * cache){
    int searchedItems = 0;
    int return_code = -1;
    int item = 0;
    
    for (int i = 0; i < 1; i++) {
      
        Question * q = mesg->questions + i;
        int type = q->QType;
        while ((item = Compare_with_db(cache, item, q)) != -1) {
            mesg->headerAA = 1;
            return_code = 1;
            if (type == DNS_RECORD_TYPE_A || type == DNS_RECORD_TYPE_CNAME || type == DNS_RECORD_TYPE_NS) {
                add_answer(mesg, & cache->records[item]);
            } else if (type == DNS_RECORD_TYPE_MX){
                DNS_Record * r = & cache->records[item];
                int ptem = 0;
                add_answer(mesg, r);
                
                Question p;
                p.QClass =  q->QClass;
                p.QType  =  DNS_RECORD_TYPE_A;
                p.QName  =  strdup(r->data.mx_record.exchange);
                
                ptem = search_db(cache, &p); 
                assert(ptem >= 0);
                add_additional(mesg, &cache->records[ptem]);
            }
            searchedItems ++;
            item ++;
        }
   
        if (searchedItems <= 0) {
            return_code = 0;
            if ((item = search_db_indirect_fromindex(cache, 0, q)) != -1) {
                add_authority(mesg, & cache->records[item]);
                searchedItems ++;
                return return_code;
            }
            
        }
      
        if (searchedItems <= 0) {
            return return_code = -1;
        }
    }
    return return_code;
}

void initdb(DataBase * db, FILE * fs){
    db->len = 0;
    
    bzero(db, sizeof(DataBase));
    
    if (fs == NULL) { return ; }
    
    char b[1024];
    
    for (int i = 0; !feof(fs); i++) {
        bzero(b, 1024);
        fscanf(fs, "%s", b);
        if (strlen(b) == 0) { break; }
        printf("Init Record: %s\n", b);
        
        DNS_Record * r = & db->records[i];
        
        
        char * last = b;
        char * token = strtok_r(b, ",", &last);
        r->original_name = strdup(token);
        r->name = getFormatedURLFromNormalURL(token);
        
   
        token = strtok_r(NULL, ",", &last);
        r->ttl = atoi(token);
        
        
        token = strtok_r(NULL, ",", &last);
        r->class = getTypeIntValue(token, DNS_CLASS_SET, sizeof(DNS_CLASS_SET)/sizeof(char*));
        
      
        token = strtok_r(NULL, ",", &last);
        r->type = getTypeIntValue(token, DNS_TYPE_SET, sizeof(DNS_TYPE_SET)/sizeof(char *));
        
      
        token = strtok_r(NULL, ",", &last);
        
        r->record = strdup(token);
        
        char * mx_pref = NULL;
        char * mx_addr = NULL;
        //different type
        switch (r->type) {
            case DNS_RECORD_TYPE_A:
                r->data.a_record.addr = inet_addr(r->record);
                break;
            case DNS_RECORD_TYPE_CNAME:
                r->data.name_record.name = str2url(r->record);
                break;
                
            case DNS_RECORD_TYPE_MX:
                mx_pref = strtok(token, ":");
                mx_addr = strtok(NULL, ":");
                mx_addr = str2url(mx_addr);
                uint16_t pref = atoi(mx_pref);
                r->data.mx_record.exchange = mx_addr;
                r->data.mx_record.preference = pref;
                break;
            default:
                fprintf(stderr, "Fall back resource not support yet !\n");
                break;
        }
        db->len += 1;
    }
    
    db->records[db->len].name = 0;
}

DataBase * newdb(const char * fname){
    FILE * fs = fopen(fname, "r");
    DataBase * db = calloc(1 , sizeof(DataBase));
    if (!fs) {
        printf("DB Initialization Failed. Will have no record in DB\n");
    }
    
    initdb(db, fs);
    return db;
}

void savedb(DataBase * db, FILE * fs){
    for (int i = 0; i < db->len; i++) {
        DNS_Record * r = & db->records[i];
        fprintf(fs, "%s,", r->name);
        fprintf(fs, "%d,", r->ttl);
        fprintf(fs, "%s,", DNS_CLASS_SET[r->class]);
        fprintf(fs, "%s,", DNS_TYPE_SET[r->type]);
        fprintf(fs, "%s", r->record);
        if (i != db->len - 1) { fprintf(fs, "\n"); }
    }
}

void addrecord_db(DataBase * db, const char * name, uint32_t ttl, DNSClass_t class, DNSType_t type, const char * record){
    DNS_Record * r = &db->records[db->len];
    r->name = strdup(name);
    r->ttl = ttl;
    r->class = class;
    r->type = type;
    r->record = strdup(record);
    db->len++;
}

DNS_Record * addrecord_db_t(DataBase * db, RR * record){
    DNS_Record * r = &db->records[db->len];
    r->name = strdup(record->name);
    r->ttl = record->rttl;
    r->class = record->rclass;
    r->type = record->rtype;
    
    // Data Init
    if (r->type == DNS_RECORD_TYPE_A) {
        r->data.a_record.addr = record->rdata.a_record.addr;
    }else if (r->type == DNS_RECORD_TYPE_MX){
        r->data.mx_record.exchange   = strdup(record->rdata.mx_record.exchange);
        r->data.mx_record.preference = record->rdata.mx_record.preference;
    }else if (r->type == DNS_RECORD_TYPE_CNAME || r->type == DNS_RECORD_TYPE_NS || r->type == DNS_RECORD_TYPE_PTR){
        r->data.name_record.name = strdup(record->rdata.name_record.name);
    }
    
    // Record Initialize
    Buffer * s = newBuffer();
    if (r->type == DNS_RECORD_TYPE_A) {
        struct sockaddr_in addr;
        addr.sin_addr.s_addr = record->rdata.a_record.addr;
        r->record = inet_ntoa(addr.sin_addr);
    }else if (r->type == DNS_RECORD_TYPE_MX){
        char preference = record->rdata.mx_record.preference + '0';
        cout(s, (char *) &preference, sizeof(char));
        put1Byte(s, (uint8_t) ':');
        char * urlstring = url2str(record->rdata.mx_record.exchange);
        cout(s, (char *) urlstring, strlen(urlstring));
        r->record = strdup(s->buffer);
        
    }else if (r->type == DNS_RECORD_TYPE_CNAME || r->type == DNS_RECORD_TYPE_NS || r->type == DNS_RECORD_TYPE_PTR){
        r->record = url2str(record->rdata.name_record.name);
    }
    
    freeBuffer(s);
    
    db->len++;
    return r;
}

int search_db(DataBase * db, Question * q){
    return Compare_with_db(db, 0, q);
}

int search_db_r(DataBase * db, RR * r){
    Question q;
    q.QClass = r->rclass;
    q.QType = r->rtype;
    q.QName = r->name;
    return Compare_with_db(db, 0, &q);
}

int search_db_indirect_fromindex(DataBase * db, int start, Question * q){
    for (int i = start; i < db->len; i++) {
        char * substring = strstr(q->QName, db->records[i].name);
        int a = substring ? 1 : 0;
        int b = db->records[i].type == DNS_RECORD_TYPE_A;
        int c = substring && strlen(substring) == strlen(db->records[i].name);
        
        if (a && b && c) {
            return i;
        }
    }
    return -1;
}


int Compare_with_db(DataBase * db, int start, Question * q){
    for (int i = start; i < db->len; i++) {
        int a = (strcmp(db->records[i].name, q->QName) == 0);
        int b = (db->records[i].type == q->QType);
        int c = (db->records[i].class == q->QClass);
        if (a && b && c) {
            return i;
        }
    }
    return -1;
}

int search_db_identical_record_fromindex(DataBase *db, int start, RR * r){
    for (int i = start; i < db->len; i++) {
        int a = (strcmp(db->records[i].name, r->name) == 0);
        int b = (db->records[i].type == r->rtype);
        int c = (db->records[i].class == r->rclass);
        
        int d = b && r->rtype == DNS_RECORD_TYPE_MX  ? strcmp(r->rdata.mx_record.exchange, db->records[i].data.mx_record.exchange) == 0 : 1;
        if (a && b && c && d) {
            return i;
        }
    }
    return -1;
}




void cacheDBRecord_if_not_found(DataBase * db, RR * r){
    if (search_db_identical_record_fromindex(db, 0, r) == -1) {
        DNS_Record * dbr = addrecord_db_t(db, r);
        printf("Cached record: "); print_cache_record(dbr);
    }
}


void add_resource(RR * mr, DNS_Record * r){
    mr->rclass = r->class;
    mr->name = strdup(r->name);
    mr->rttl = r->ttl;
    mr->rtype = r->type;
    
    switch (r->type) {
        case DNS_RECORD_TYPE_A:
            mr->rdata.a_record.addr = inet_addr(r->record);
            mr->rdlength = sizeof(in_addr_t);
            break;
        case DNS_RECORD_TYPE_NS:
        case DNS_RECORD_TYPE_PTR:
        case DNS_RECORD_TYPE_CNAME:
            if (strcmp(r->data.name_record.name, "") == 0) {
                mr->rdata.name_record.name = strdup("");
                mr->rdlength = 1;
                break;
            }
            mr->rdata.name_record.name = strdup(r->data.name_record.name);
            mr->rdlength = strlen(r->data.name_record.name) + 1;
            break;
        case DNS_RECORD_TYPE_MX:
            mr->rdata.mx_record.exchange = strdup(r->data.mx_record.exchange);
            mr->rdata.mx_record.preference = r->data.mx_record.preference;
            mr->rdlength = strlen(mr->rdata.mx_record.exchange) + 1 + sizeof(uint16_t);
            break;
        default:
            break;
    }
}

void add_answer(Dns_Packet * msg, DNS_Record * r){
    RR * mr = &msg->answers[msg->answerNum++];
    add_resource(mr, r);
}

void add_authority(Dns_Packet * msg, DNS_Record * r){
    RR * mr = &msg->authorities[msg->authorityNum++];
    add_resource(mr, r);
}

void add_additional(Dns_Packet * msg, DNS_Record * r){
    RR * mr = &msg->additionals[msg->additionalNum];
    msg->additionalNum++;
    add_resource(mr, r);
}
