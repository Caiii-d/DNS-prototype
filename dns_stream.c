#include "dns_stream.h"

int getURLString(char * des, Buffer * src){
    uint8_t len;
    int original_pos = src->cursor_pos;
    while ((len = read_8bit_from_buffer(src)) != 0) {
        des[0] = len; 
        des++;
        Buffer_read(des, src, len); 
        des += len;
    }
    des[0] = 0;
    
    return src->cursor_pos - original_pos;
}

int putURLString(Buffer * des, char * src){
    uint8_t len;
    const char * src_p = src;
    
    len = src[0];
    while (len != 0) {
        put1Byte(des, len); src++;
        cout(des, src, len); src += len;
        len = src[0];
    }
    
    put1Byte(des, len);
    return (int)(src - src_p);
}

char * getURLString_allocated(Buffer * src){
    char * url = calloc(256, sizeof(char));
    getURLString(url, src);
    char * ret = strdup(url);
    free(url);
    return ret;
}

uint16_t packHeaderFlags(Header * head){
    uint16_t flags = 0;
    flags |= head->headerQR ? 0x8000 : 0;
    flags |= head->headerOpcode << 11;
    flags |= head->headerAA ? 0x0400 : 0;
    flags |= head->headerTC ? 0x0200 : 0;
    flags |= head->headerRD ? 0x0100 : 0;
    flags |= head->headerRA ? 0x0080 : 0;
    flags |= head->headerrcode;
    return flags;
}

void unpackHeaderFlags(Header * head, uint16_t flags){
    head->headerQR     = flags & 0x8000 ? 1 : 0;
    head->headerOpcode = (flags & 0x7800) >> 11;
    head->headerAA     = flags & 0x0400 ? 1 : 0;
    head->headerTC     = flags & 0x0200 ? 1 : 0;
    head->headerRD     = flags & 0x0100 ? 1 : 0;
    head->headerRA     = flags & 0x0080 ? 1 : 0;
    head->headerrcode  = flags & 0x000f;
}

ssize_t SendTCP_Buffer(int sock, Buffer * buf){
    *((uint16_t *) buf->buffer) =  (uint16_t) buf->content_len;
    return SendTCP(sock, buf->buffer, buf->content_len);
}

ssize_t RecvTCP_Buffer(int sock, Buffer * buf){
    buf->content_len = (int) RecvTCP(sock, buf->buffer, 4096);
    read_16bit_from_buffer(buf);
    printf("<<< Recv %zd bytes\n", buf->content_len);
    return buf->content_len;
}

ssize_t SendUDP_Buffer(int sock, Buffer * buf, struct sockaddr_in * addr){
    ssize_t sc = sendto(sock, (void *)(buf->buffer), buf->content_len, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
    printf(">>> SentUDP %zd bytes\n", sc);
    return sc;
}

ssize_t RecvUDP_Buffer(int sock, Buffer * buf, struct sockaddr_in * addr){
    socklen_t t = sizeof(struct sockaddr_in);
    ssize_t rc = (buf->content_len = (int) recvfrom(sock, (void *)(buf->buffer), 4096, 0, (struct sockaddr *)addr, &t));
    printf("<<< Recv %zd bytes\n", rc);
    return rc;
}

void SendTCP_Message(int sock, Dns_Packet * mesg){
    Buffer * s = newBuffer();
    cout_TCP_Header(s);
    handle_out_packet(s, mesg);
    SendTCP_Buffer(sock, s);
    freeBuffer(s);
}

Dns_Packet * RecvTCP_Message(int sock){
    Dns_Packet * mesg = newPacket();
    Buffer * s = newBuffer();
    if (RecvTCP_Buffer(sock, s) < 0) { freeMessage(mesg); return NULL; }
    handle_in_packet(mesg, s);
    return mesg;
}

void SendUDP_Message(int sock, Dns_Packet * mesg, struct sockaddr_in * toAddr){
    Buffer * s = newBuffer();
    handle_out_packet(s, mesg);
    SendUDP_Buffer(sock, s, toAddr);
    freeBuffer(s);
}


Dns_Packet * RecvUDP_Message(int sock, struct sockaddr_in ** fromAddr){
    Dns_Packet * mesg = newPacket();
    Buffer * s = newBuffer();
    if (!fromAddr) {
        fromAddr = calloc(1, sizeof(struct sockaddr_in *));
    }
    *fromAddr = newSocketaddr_t(0, 0);
    if (RecvUDP_Buffer(sock, s, *fromAddr) < 0) { freeMessage(mesg); return NULL; }
    handle_in_packet(mesg, s);
    return mesg;
}

void cout_TCP_Header(Buffer * s){
    put2Bytes(s, 0);
}

int put1Byte(Buffer * des, uint8_t src){
    return cout(des, (char *) & src, sizeof(uint8_t));
}

int put2Bytes(Buffer * des, uint16_t src){
    src = htons(src);
    return cout(des, (char *) & src, sizeof(uint16_t));
}

int put4Bytes(Buffer * des, uint32_t src){
    src = htonl(src);
    return cout(des, (char *) & src, sizeof(uint32_t));
}

int cout(Buffer * des, char * src, size_t size){
    memcpy(&des->buffer[des->content_len], src, size);
    des->content_len += size;
    return (int) size;
}

void handle_out_packet(Buffer * s, Dns_Packet * mesg){
    
    Header * head = (Header *) mesg;
    handle_out_Header(s, head);
    
    for (int i = 0; i < mesg->queryNum; i++) {
        Question * q = & mesg->questions[i];
        handle_out_Question(s, q);
    }
    
    for (int i = 0; i < mesg->answerNum; i++) {
        RR * r = & mesg->answers[i];
        handle_out_RR(s, r);
    }
    
    for (int i = 0; i < mesg->authorityNum; i++) {
        RR * r = & mesg->authorities[i];
        handle_out_RR(s, r);
    }
    
    for (int i = 0; i < mesg->additionalNum; i++) {
        RR * r = & mesg->additionals[i];
        handle_out_RR(s, r);
    }
    
}

void handle_out_Header(Buffer * s, Header * head){
    put2Bytes(s, head->headerID);
    uint16_t flags = packHeaderFlags(head);
    put2Bytes(s, flags);
    put2Bytes(s, head->queryNum);
    put2Bytes(s, head->answerNum);
    put2Bytes(s, head->authorityNum);
    put2Bytes(s, head->additionalNum);
}

void handle_out_Question(Buffer * s, Question * q){
    putURLString(s, q->QName);
    put2Bytes(s, q->QType);
    put2Bytes(s, q->QClass);
}

void handle_out_RR(Buffer * s, RR * r){
    putURLString(s, r->name);
    put2Bytes(s, r->rtype);
    put2Bytes(s, r->rclass);
    put4Bytes(s, r->rttl);
    put2Bytes(s, r->rdlength);
    handle_out_RData(s, r);
}

void handle_out_RData(Buffer * s, RR * r){
    Rdata * d = & r->rdata;
    DNSType_t type = r->rtype;
    
    switch (type) {
        case DNS_RECORD_TYPE_A:
            put4Bytes(s, htonl(d->a_record.addr));
            break;
        case DNS_RECORD_TYPE_MX:
            put2Bytes(s, d->mx_record.preference);
            putURLString(s, d->mx_record.exchange);
            break;
        case DNS_RECORD_TYPE_CNAME:
            putURLString(s, d->name_record.name);
            break;
        default:
            break;
    }
    
}


int Buffer_read(char * des, Buffer * src, size_t size){
    if (src->cursor_pos > src->content_len) {
        printf("Parse Error: %d (> %d)\n", src->cursor_pos, src->content_len);
    }
    memcpy(des, &src->buffer[src->cursor_pos], size);
    src->cursor_pos += size;
    return (int) size;
}

void handle_in_packet(Dns_Packet * packet, Buffer * s){
    Header * head = (Header *) packet;
    handle_in_Header(head, s);
    for (int i = 0; i < packet->queryNum; i++) {
        Question * q = & packet->questions[i];
        handle_in_Question(q, s);
    }
    
    for (int i = 0; i < packet->answerNum; i++) {
        RR * r = & packet->answers[i];
        handle_in_RR(r, s);
    }
    
    for (int i = 0; i < packet->authorityNum; i++) {
        RR * r = & packet->authorities[i];
        handle_in_RR(r, s);
        
    }
    
    for (int i = 0; i < packet->additionalNum; i++) {
        RR * r = & packet->additionals[i];
        handle_in_RR(r, s);
    }
}

void handle_in_Header(Header * head, Buffer * s){
    head->headerID = read_16bit_from_buffer(s);
    uint16_t flags = read_16bit_from_buffer(s);
    unpackHeaderFlags(head, flags);
    head->queryNum = read_16bit_from_buffer(s);
    head->answerNum = read_16bit_from_buffer(s);
    head->authorityNum = read_16bit_from_buffer(s);
    head->additionalNum = read_16bit_from_buffer(s);
}

void handle_in_Question(Question * q, Buffer *s){
    q->QName = getURLString_allocated(s);
    q->QType = read_16bit_from_buffer(s);
    q->QClass = read_16bit_from_buffer(s);
}

void handle_in_RR(RR * r, Buffer * s){
    r->name = getURLString_allocated(s);
    r->rtype = read_16bit_from_buffer(s);
    r->rclass = read_16bit_from_buffer(s);
    r->rttl = read_32bit_from_buffer(s);
    r->rdlength = read_16bit_from_buffer(s);
    // Resource Record encoder and decoder
    handle_in_RData(r, s);
}

//
void handle_in_RData(RR * r, Buffer * s){
    Rdata * d = & r->rdata;
    int type = r->rtype;
    switch (type) {
        case DNS_RECORD_TYPE_A:
            d->a_record.addr = ntohl(read_32bit_from_buffer(s));
            break;
        case DNS_RECORD_TYPE_MX:
            d->mx_record.preference = read_16bit_from_buffer(s);
            d->mx_record.exchange = getURLString_allocated(s);
            break;
        case DNS_RECORD_TYPE_CNAME:
            d->name_record.name = getURLString_allocated(s);
            break;
        default:
            break;
    }
}

uint8_t read_8bit_from_buffer(Buffer * src){
    uint8_t tmp; 
    Buffer_read((char *) &tmp, src, sizeof(uint8_t)); 
    return tmp;
}

uint16_t read_16bit_from_buffer(Buffer * src){
    uint16_t tmp; 
	Buffer_read((char *) &tmp, src, sizeof(uint16_t));
    return ntohs(tmp);
}

uint32_t read_32bit_from_buffer(Buffer * src){
    uint32_t tmp; 
    Buffer_read((char *) &tmp, src, sizeof(uint32_t));
    return ntohl(tmp);
}

void initBuffer(Buffer * s){
    bzero( (void *) s, sizeof(Buffer));
}

Buffer * newBuffer(){
    Buffer * s = calloc(1, sizeof(Buffer));
    return s;
}

void freeBuffer(Buffer * s){
    free(s);
}

