#include "dns.h"

char * str2url(const char * url){
    
    if (!url) {
        fprintf(stderr, "%s: Empty string\n", __FUNCTION__);
        return NULL;
    }
    
    // 1. Root => "." or ""
    if (strlen(url) == 0 || (strlen(url) == 1 && url[0] == '.')) {
        char * buf = calloc(1, sizeof(char));
        buf[0] = 0;
        return buf;
    }
    
    ssize_t urllen = strlen(url); // final url length
    if ((int)(strrchr(url, '.') - url) == urllen - 1) { urllen -= 1; }
    
    ssize_t final_url_len = urllen + 2;
    
    char * buf = calloc(128, sizeof(char));
    
    ssize_t buflen = 0;
    
    char * turl = strdup(url);
    
    char * tok = strtok(turl, ".");
    
    while (tok) {
        uint8_t len = strlen(tok);
        memcpy(&buf[buflen], &len, sizeof(uint8_t));
        buflen += 1;
        memcpy(&buf[buflen], tok, len);
        buflen += len;
        tok = strtok(NULL, ".");
    }
    
    buf[buflen++] = 0;
    
    if (final_url_len != buflen) {
        fprintf(stderr, "%s: Invalid string %s\n", __FUNCTION__, url);
        free(buf); free(turl);
        return NULL;
    }
    
    
    
    buf = realloc(buf, buflen);
    
    return buf;
    
}

char * url2str(const char * ziped_url){
    if (!ziped_url) {
        fprintf(stderr, "%s(): Empty string\n", __FUNCTION__);
        return NULL;
    }
    
    if (strlen(ziped_url) == 0) {
        return strdup(".");
    }
    
    char * ret = strdup(ziped_url);
    
    char * p = ret;
    uint8_t len;
    
    while ((len = (uint8_t)p[0]) != 0 && (p[0] = '.') && (p += len + 1)) ;
    
    p[0] = 0;
    
    char * r = strdup(ret+1);
    
    free(ret);
    
    return r;
    
}

int getEnumValueFromSet(const char * str, const char ** set, int setsize){
    for (int i = 1; i < setsize/sizeof(char *); i++) {
        if (strcmp(str, set[i]) == 0) {
            return i;
        }
    }
    fprintf(stderr, "%s(): no such value : %s\n", __FUNCTION__, str);
    return -1;
}



void make_header_query(Dns_Packet * mesg, int recursive_desired, int numQuestions){
    Header * head = (Header * )mesg;
    head -> headerID = rand();
    head -> headerQR = HEADER_FLAG_QR_ISQUERY;
    head -> headerOpcode = HEADER_FLAG_OPCODE_STANDARDQUERY;
    head -> headerAA = 0;
    head -> headerTC = 0;
    head -> headerRD = recursive_desired;
    head -> headerRA = 0;
    head -> headerz =  0;
    head -> headerrcode = rcode_good;
    head -> queryNum = numQuestions; 
    head -> answerNum = 0;
    head -> authorityNum = 0; 
    head -> additionalNum = 0;
}

int make_question_query(Question * q, const char * type, const char * name ){
    q->QName = str2url(name);
    q->QType = getEnumValueFromSet(type, DNS_TYPE_SET, sizeof(DNS_TYPE_SET));
    q->QClass = DNS_CLASS_TYPE_IN;
    
    if (q->QType <= 0 || !q->QName) {
        fprintf(stderr, "%s(): questions invalid\n", __FUNCTION__);
        return -1;
    }
    return 0;
}

void add_question_query(Dns_Packet * mesg, const char * type, const char * name ){
    make_question_query(mesg->questions + mesg->queryNum, type, name);
    mesg->queryNum += 1;
    make_header_query(mesg, 1, mesg->queryNum); 
}

int make_question_query_r(Question * q, int type, const char * name_alloced ){
    q->QName = (char *) name_alloced;
    q->QType = type;
    q->QClass = DNS_CLASS_TYPE_IN;
    
    if (q->QType <= 0 || !q->QName) {
        fprintf(stderr, "Invalid questions in function make_question_query_r()\n");
        return -1;
    }

    return 0;
}

void add_question_query_r(Dns_Packet * mesg, int type, const char * name_alloced ){
    make_question_query_r(mesg->questions + mesg->queryNum, type, name_alloced);
    mesg->queryNum += 1;
    make_header_query(mesg, 1, mesg->queryNum); 
}


// - Mark : Print Functions

int print_header(Header * h){
    printf("| id:%d\tstatus:%s\n", h->headerID, RCODE_SET[h->headerrcode]);
    printf("| flags %s%s%s%s%s\n",
           h->headerQR ? "qr ": "",
           h->headerAA ? "aa " : "",
           h->headerTC ? "tc " : "",
           h->headerRD ? "rd " : "",
           h->headerRA ? "ra " : "");
    printf("| QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL %d\n", h->queryNum, h->answerNum, h->authorityNum, h->additionalNum);
    return 0;
}

int print_question(Question * q){
    char * p = url2str(q->QName);
    
    printf("%s\t%s\t%s\n", p, DNS_TYPE_SET[q->QType] , DNS_CLASS_SET[q->QClass]);
    free(p);
    return 0;
}

int print_resource_record(RR * r){
    char * p = url2str(r->name);
    printf("%s\t%s\t%s\t%d\tdatalen = %d\t ", p, DNS_TYPE_SET[r->rtype], DNS_CLASS_SET[r->rclass], r->rttl, r->rdlength);
    free(p);
    
    Rdata * d = &r->rdata;
    
    struct in_addr addr;
    
    switch (r->rtype) {
        case DNS_RECORD_TYPE_A:
            addr.s_addr = d->a_record.addr;
            printf("%s\n", inet_ntoa(addr)); break;
        case DNS_RECORD_TYPE_MX:
            printf("%d\t%s\n", d->mx_record.preference, url2str(d->mx_record.exchange)); break;
        case DNS_RECORD_TYPE_NS:
        case DNS_RECORD_TYPE_PTR:
        case DNS_RECORD_TYPE_CNAME:
            printf("%s\n", url2str(d->name_record.name)); break;
            break;
            
        default:
            break;
    }
    
    return 0;
}



void free_resouce_record(RR * r){
    free(r->name);
    switch (r->rtype) {
        case DNS_RECORD_TYPE_MX:
            free(r->rdata.mx_record.exchange);
            break;
        case DNS_RECORD_TYPE_NS: case DNS_RECORD_TYPE_PTR: case DNS_RECORD_TYPE_CNAME:
            free(r->rdata.name_record.name);
            break;
        case DNS_RECORD_TYPE_A: default:
            break;
    }
}

void freeMessage(Dns_Packet * message){
    // 1. Read Header
    Header * head = (Header *) message;
    
    // 2. Read Questions
    for (int i = 0; i < head->queryNum; i++) {
        Question * q = message->questions + i;
        free(q->QName);
    }
    
    // 3. Read Answers
    for (int i = 0; i < head->answerNum; i++) {
        RR * r = message->answers + i;
        free_resouce_record(r);
        
    }
    
    // 4. Read Authorities
    for (int i = 0; i < head->authorityNum; i++) {
        RR * r = message->authorities + i;
        free_resouce_record(r);
    }
    
    // 5. Read Additionals
    for (int i = 0; i < head->additionalNum; i++) {
        RR * r = message->additionals + i;
        free_resouce_record(r);
    }
    
}

void initMessage(Dns_Packet * message){
    if (!message) { return; }
    bzero(message, sizeof(Dns_Packet));
}

Dns_Packet * newPacket(){
    Dns_Packet * recvPack = calloc(1, sizeof(Dns_Packet));
    
    //initMessage(mesg);
    return recvPack;
}


void print_message(Dns_Packet * message){
    
    printf("* - * - * - * - *\n");
    // 1. Read Header
    Header * head = (Header *) message;
    printf("$ {Header}\n");
    print_header(head);
    
    // 2. Read Questions
    if (head->queryNum) {
        printf("$ {Question Section}\n");
    }
    for (int i = 0; i < head->queryNum; i++) {
        Question * q = message->questions + i;
        printf("| {%d} ", i);
        print_question(q);
    }
    
    // 3. Read Answers
    if (head->answerNum) {
        printf("$ {Answer Section}\n");
    }
    for (int i = 0; i < head->answerNum; i++) {
        RR * r = message->answers + i;
        printf("| {%d} ", i);
        print_resource_record(r);
    }
    
    // 4. Read Authorities
    if (head->authorityNum) {
        printf("$ {Authority Section}\n");
    }
    
    for (int i = 0; i < head->authorityNum; i++) {
        RR * r = message->authorities + i;
        printf("| {%d} ", i);
        print_resource_record(r);
    }
    
    // 5. Read Additionals
    if (head->additionalNum) {
        printf("$ {Additional Section}\n");
    }
    for (int i = 0; i < head->additionalNum; i++) {
        RR * r = message->additionals + i;
        printf("| {%d} ", i);
        print_resource_record(r);
    }
    
    printf("- - - - -\n");
    
}

void trace_message(Dns_Packet * message){
    
    Header * head = (Header *) message;
    
    // 3. Read Answers
    if (head->answerNum) {
        printf("\n{Answer Section}\n");
    }
    for (int i = 0; i < head->answerNum; i++) {
        RR * r = message->answers + i;
        printf("{%d} ", i);
        print_resource_record(r);
    }
    
    // 4. Read Authorities
    if (head->authorityNum) {
        printf("\n{Authority Section}\n");
    }
    
    for (int i = 0; i < head->authorityNum; i++) {
        RR * r = message->authorities + i;
        printf("{%d} ", i);
        print_resource_record(r);
    }
    
    // 5. Read Additionals
    if (head->additionalNum) {
        printf("{Additional Section}\n");
    }
    for (int i = 0; i < head->additionalNum; i++) {
        RR * r = message->additionals + i;
        printf("[%d] ", i);
        print_resource_record(r);
    }
    printf("\n");
}
