/* See feature_test_macros(7) */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <simple_protobuf.h>
#include "crypto.h"
#include "config.h"

#if !__APPLE__
    #include <sys/sendfile.h> 
#else
    struct sf_hdtr hdtr; 
#endif

static int sockfd;
static char buf[BUFSIZ];
static char bufr[BUFSIZ];
static struct sockaddr_in their_addr;
static pthread_t thread;
static uint32_t file_size;
static int recv_bin = 0;
static config_t conf;

#define DEBUG

void getMessage(void *p) {
    int c = 0, offset = 0;
    cmdpacket_t cp = (cmdpacket_t)bufr;
    while(offset >= CMDPACKET_HEAD_LEN || (c = recv(sockfd, bufr+offset, CMDPACKET_HEAD_LEN-offset, MSG_WAITALL)) > 0) {
        #ifdef DEBUG
            printf("Recv %d bytes.\n", c);
        #endif
        if(recv_bin) {
            if(~recv_bin) {
                recv_bin = -1;
                int l = strlen(buf+4);
                char savepath[l+1];
                memcpy(savepath, buf+4, l+1);
                printf("Save path: ");
                puts(savepath);
                int i = 0;
                while(bufr[i] != '$') i++;
                while(bufr[i] != '$') recv(sockfd, bufr+i++, 1, MSG_WAITALL);
                bufr[i] = 0;
                unsigned int datalen;
                sscanf(bufr, "%u", &datalen);
                #ifdef DEBUG
                    printf("raw data len: %d\n", datalen);
                #endif
                if(datalen == 0) {
                    puts("raw data is empty, truncate file.");
                    fclose(fopen(savepath, "wb+"));
                } else {
                    char* data = malloc(datalen);
                    offset = c - ++i;
                    if(offset > 0) {
                        memcpy(data, bufr+i, offset);
                        #ifdef DEBUG
                            printf("copy %d bytes data that had been received.\n", offset);
                        #endif
                    }
                    else offset = 0;
                    if(datalen-offset == recv(sockfd, data+offset, datalen-offset, MSG_WAITALL)) {
                        //FILE* fp = fopen("raw_before_dec", "wb+");
                        //fwrite(data, datalen, 1, fp);
                        //fclose(fp);
                        off_t tmp = datalen;
                        char* newdata = raw_decrypt(data, &tmp, 0, conf.pwd);
                        if(newdata) {
                            printf("raw data len after decode: %d\n", (int)tmp);
                            FILE* fp = fopen(savepath, "wb+");
                            fwrite(newdata, (size_t)tmp, 1, fp);
                            fclose(fp);
                            free(newdata);
                            puts("recv raw data succeed.");
                        } else puts("decode raw data error.");
                    } else puts("recv raw data error.");
                    free(data);
                }
                recv_bin = offset =  0;
            }
        } else {
            offset += c;
            #ifdef DEBUG
                printf("[handle] Get %d bytes, total: %d.\n", c, offset);
            #endif
            if(offset < CMDPACKET_HEAD_LEN) break;
            if(offset < CMDPACKET_HEAD_LEN+cp->datalen) {
                c = recv(sockfd, bufr+offset, CMDPACKET_HEAD_LEN+cp->datalen-offset, MSG_WAITALL);
                if(c <= 0) break;
                else {
                    offset += c;
                    #ifdef DEBUG
                        printf("[handle] Get %d bytes, total: %d.\n", c, offset);
                    #endif
                }
            }
            c = CMDPACKET_HEAD_LEN+cp->datalen; // 暂存 packet len
            if(offset < c) break;
            #ifdef DEBUG
                printf("[handle] Decrypt %d bytes data...\n", (int)cp->datalen);
            #endif
            if(cmdpacket_decrypt(cp, 0, conf.pwd)) {
                cp->data[cp->datalen] = 0;
                #ifdef DEBUG
                    printf("[normal] Get %u bytes packet with data: %s\n", offset, cp->data);
                #endif
                printf("[%d] recv ack: %s\n", (int)cp->cmd, cp->data);
            }
            if(offset > c) {
                offset -= c;
                memmove(bufr, bufr+c, offset);
                c = 0;
            } else offset = 0;
            #ifdef DEBUG
                printf("offset after analyzing packet: %d\n", offset);
            #endif
        }
    }
}

off_t file_size_of(const char* fname) {
    struct stat statbuf;
    if(stat(fname, &statbuf)==0) return statbuf.st_size;
    else return -1;
}

void send_cmd(int accept_fd, cmdpacket_t p) {
    #ifdef DEBUG
        printf("send %d bytes encrypted data with %d bytes head.\n", p->datalen, CMDPACKET_HEAD_LEN);
        printf("raw packet: ");
        for(int i = 0; i < CMDPACKET_HEAD_LEN+p->datalen; i++) printf("%02x", ((uint8_t*)p)[i]);
        putchar('\n');
    #endif
    if(!~send(accept_fd, (void*)p, CMDPACKET_HEAD_LEN+p->datalen, 0)) puts("Send data error.");
    else puts("Send data succeed.");
}

int main(int argc, char *argv[]) {   // usage: ./client cfg.sp host port
    if(argc != 4) {
        puts("usage: cfg.sp host port");
        return 0;
    }
    FILE* fp = fopen(argv[1], "rb");
    if(fp == NULL) {
        fprintf(stderr, "Error opening config file: %s", argv[1]);
        perror("fopen");
        return 1;
    }
    SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
    if(!spb) {
        fprintf(stderr, "Error reading config file: %s\n", argv[1]);
        return 2;
    }
    conf = *(config_t*)(spb->target);
    fclose(fp);
    ssize_t numbytes;
    puts("break!");
    while((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1);
    puts("Get sockfd");
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(atoi(argv[3]));
    their_addr.sin_addr.s_addr=inet_addr(argv[2]);
    bzero(&(their_addr.sin_zero), 8);
    while(connect(sockfd,(struct sockaddr*)&their_addr,sizeof(struct sockaddr)) == -1);
    puts("Connected to server");
    if(!pthread_create(&thread, NULL, (void*)&getMessage, NULL)) {
        puts("Thread create succeeded");
        init_crypto();
        reset_seq(0);
        while(1) {
            printf("Enter command:");
            scanf("%s",buf);
            if(!strcmp(buf, "bin")) recv_bin = !recv_bin;
            else if(!strcmp(buf, "file")) {
                printf("Enter file path:");
                scanf("%s",buf);
                printf("Open:");
                puts(buf);
                FILE *fp = NULL;
                fp = fopen(buf, "rb");
                if(fp) {
                    off_t len = 0;
                    file_size = (uint32_t)file_size_of(buf);
                    #if __APPLE__
                        struct iovec headers;
                        headers.iov_base = &file_size;
                        headers.iov_len = sizeof(uint32_t);
                        hdtr.headers = &headers;
                        hdtr.hdr_cnt = 1;
                        hdtr.trailers = NULL;
                        hdtr.trl_cnt = 0;
                        if(!sendfile(fileno(fp), sockfd, 0, &len, &hdtr, 0)) puts("Send file success.");
                        else puts("Send file error.");
                    #else
                        send(sockfd, &file_size, sizeof(uint32_t), 0);
                        if(!sendfile(sockfd, fileno(fp), &len, file_size)) puts("Send file success.");
                        else puts("Send file error.");
                    #endif
                    fclose(fp);
                    printf("Send count: %d\n", (int)len);
                } else puts("Open file error!");
            }
            else {
                buf[3] = 0;
                cmdpacket_t p = malloc(CMDPACKET_LEN_MAX);
                if(!strcmp(buf, "set")) {
                    p->cmd = CMDSET;
                    p->datalen = strlen(buf+4);
                    cmdpacket_encrypt(p, 0, conf.sps, buf+4);
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "dat")) {
                    p->cmd = CMDDAT;
                    p->datalen = strlen(buf+4);
                    cmdpacket_encrypt(p, 0, conf.sps, buf+4);
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "get")) {
                    p->cmd = CMDGET;
                    p->datalen = strlen(buf+4);
                    cmdpacket_encrypt(p, 0, conf.pwd, (const char *)&buf+4);
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "cat")) {
                    p->cmd = CMDCAT;
                    p->datalen = 4;
                    recv_bin = 1;
                    cmdpacket_encrypt(p, 0, conf.pwd, (const char *)&"fill");
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "del")) {
                    p->cmd = CMDDEL;
                    p->datalen = strlen(buf+4);
                    cmdpacket_encrypt(p, 0, conf.sps, buf+4);
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "md5")) {
                    if(strlen(buf+4) != 32) puts("md5 len mismatch.");
                    else {
                        p->cmd = CMDMD5;
                        p->datalen = 16;
                        for(int i = 0; i < 16; i++) sscanf(buf+4+i*2, "%02x", (unsigned int*)&p->data[i]);
                        printf("Read md5:");
                        for(int i = 0; i < 16; i++) printf("%02x", (uint8_t)(p->data[i]));
                        putchar('\n');
                        cmdpacket_encrypt(p, 0, conf.pwd, (const char *)&p->data);
                        send_cmd(sockfd, p);
                        free(p);
                    }
                } else if(!strcmp(buf, "end")) {
                    p->cmd = CMDEND;
                    p->datalen = 4;
                    cmdpacket_encrypt(p, 0, conf.pwd, (const char *)&"fill");
                    send_cmd(sockfd, p);
                    free(p);
                    exit(EXIT_SUCCESS);
                } else puts("no such cmd");
            }
            sleep(1);
        }
    } else perror("Create msg thread failed");
    close(sockfd);
    return 0;
}
