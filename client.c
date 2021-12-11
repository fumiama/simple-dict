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
#include "crypto.h"

#if !__APPLE__
    #include <sys/sendfile.h> 
#else
    struct sf_hdtr hdtr; 
#endif

int sockfd;
char buf[BUFSIZ];
char bufr[BUFSIZ];
struct sockaddr_in their_addr;
pthread_t thread;
uint32_t file_size;
int recv_bin = 0;

void getMessage(void *p) {
    int c = 0, offset = 0;
    CMDPACKET* cp = bufr;
    while((c = recv(sockfd, bufr+offset, CMDPACKET_HEAD_LEN-offset, MSG_WAITALL)) > 0) {
        printf("Recv %d bytes: ", c);
        if(recv_bin) {
            recv_bin = 0;
            int i = 0;
            bufr[0] = 0;
            while(bufr[i] != '$') recv(sockfd, bufr+i, 1, MSG_WAITALL);
            bufr[i] = 0;
            off_t datalen;
            sscanf(bufr, "%d", &datalen);
            printf("raw data len: %d\n", datalen);
            char* data = malloc(datalen);
            if(datalen == recv(sockfd, data, datalen, MSG_WAITALL)) {
                raw_decrypt(data, &datalen, 0, "testpwd");
                printf("raw data len after decode: %d\n", datalen);
                FILE* fp = fopen("rawdata.bin", "w+");
                fwrite(data, datalen, 1, fp);
                fclose(fp);
                free(data);
                puts("recv raw data succeed.");
            } else {
                puts("recv raw data error.");
                free(data);
                break;
            }
        } else {
            offset += c;
            if(offset < CMDPACKET_HEAD_LEN) {
                puts("recv head error.");
                break;
            }
            c = recv(sockfd, bufr+offset, CMDPACKET_HEAD_LEN+cp->datalen-offset, MSG_WAITALL);
            if(c <= 0) {
                puts("on recv body error.");
                break;
            } else offset += c;
            if(offset < CMDPACKET_HEAD_LEN+cp->datalen) {
                puts("after recv body error.");
                break;
            }
            if(cmdpacket_decrypt(cp, index, "testpwd")) {
                cp->data[cp->datalen] = 0;
                printf("[normal] Get %u bytes data: %s\n", offset, cp->data);
                switch(cp->cmd) {
                    case CMDACK:
                        printf("recv ack: %s\n", cp->data);
                    break;
                    case CMDEND:
                    default: return; break;
                }
            }
        }
    }
}

off_t file_size_of(const char* fname) {
    struct stat statbuf;
    if(stat(fname, &statbuf)==0) return statbuf.st_size;
    else return -1;
}

void send_cmd(int accept_fd, CMDPACKET* p) {
    printf("send %d bytes encrypted data with %d bytes head.\n", p->datalen, CMDPACKET_HEAD_LEN);
    if(!~send(accept_fd, (void*)p, CMDPACKET_HEAD_LEN+p->datalen, 0)) puts("Send data error");
    else puts("Send data succeed.");
}

int main(int argc,char *argv[]) {   //usage: ./client host port
    ssize_t numbytes;
    puts("break!");
    while((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1);
    puts("Get sockfd");
    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(atoi(argv[2]));
    their_addr.sin_addr.s_addr=inet_addr(argv[1]);
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
                    printf("Send count:%u\n", len);
                } else puts("Open file error!");
            } else if(!strcmp(buf, "2md5")) {
                uint8_t md5_vals[16];
                printf("Enter md5 string:");
                for(int i = 0; i < 16; i++) scanf("%02x", &md5_vals[i]);
                printf("Read md5:");
                for(int i = 0; i < 16; i++) printf("%02x", (uint8_t)(md5_vals[i]));
                putchar('\n');
                send(sockfd, md5_vals, 16, 0);
            }
            else {
                buf[3] = 0;
                if(!strcmp(buf, "set")) {
                    CMDPACKET* p = malloc(CMDPACKET_HEAD_LEN+strlen(buf+4));
                    p->cmd = CMDSET;
                    p->datalen = strlen(buf+4);
                    memcpy(p->data, buf+4, p->datalen);
                    cmdpacket_encrypt(p, 0, "testsps");
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "get")) {
                    CMDPACKET* p = malloc(CMDPACKET_HEAD_LEN+strlen(buf+4));
                    p->cmd = CMDGET;
                    p->datalen = strlen(buf+4);
                    memcpy(p->data, buf+4, p->datalen);
                    cmdpacket_encrypt(p, 0, "testpwd");
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "cat")) {
                    CMDPACKET* p = malloc(CMDPACKET_HEAD_LEN+strlen(buf+4));
                    p->cmd = CMDCAT;
                    p->datalen = 4;
                    memcpy(p->data, "fill", p->datalen);
                    cmdpacket_encrypt(p, 0, "testpwd");
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "del")) {
                    CMDPACKET* p = malloc(CMDPACKET_HEAD_LEN+strlen(buf+4));
                    p->cmd = CMDDEL;
                    p->datalen = strlen(buf+4);
                    memcpy(p->data, buf+4, p->datalen);
                    cmdpacket_encrypt(p, 0, "testsps");
                    send_cmd(sockfd, p);
                    free(p);
                } else if(!strcmp(buf, "end")) {
                    CMDPACKET* p = malloc(CMDPACKET_HEAD_LEN+strlen(buf+4));
                    p->cmd = CMDEND;
                    p->datalen = 4;
                    memcpy(p->data, "fill", p->datalen);
                    cmdpacket_encrypt(p, 0, "testpwd");
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
