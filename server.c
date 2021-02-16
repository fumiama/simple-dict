#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int fd, accept_fd;
ssize_t numbytes;
socklen_t struct_len = sizeof(struct sockaddr_in);
struct sockaddr_in server_addr;
struct sockaddr_in client_addr;
char buff[BUFSIZ];
FILE *fp = NULL;

struct DICTBLK{
    char key[255];
    u_char keysize;
    char data[255];
    u_char datasize;
};
typedef struct DICTBLK DICTBLK;
#define DICTBLKSZ sizeof(DICTBLK)
DICTBLK dict;

#define showUsage(program) printf("Usage: %s listen_port try_times dict_file\n", program)

int bindServer(uint16_t port, u_int try_times) {
    int fail_count = 0;
    int result = -1;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero), 8);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    while(!~(result = bind(fd, (struct sockaddr *)&server_addr, struct_len)) && fail_count++ < try_times) sleep(1);
    if(!~result && fail_count >= try_times) {
        perror("Bind server failure!");
        return 0;
    } else{
        puts("Bind server success!");
        return 1;
    }
}

int listenSocket(u_int try_times) {
    int fail_count = 0;
    int result = -1;
    while(!~(result = listen(fd, 10)) && fail_count++ < try_times) sleep(1);
    if(!~result && fail_count >= try_times) {
        perror("Listen failed!");
        return 0;
    } else{
        puts("Listening....");
        return 1;
    }
}

int sendData(char *data, size_t length) {
    if(send(accept_fd, data, length, 0) < 0) {
        perror("Send data error");
        return 0;
    } else {
        printf("Send data: ");
        while(length--) putchar(*data++);
        putchar('\n');
        return 1;
    }
}

int s0_init(int *s) {
    if(!strcmp("get", buff)) *s = 1;
    else if(!strcmp("set", buff)) *s = 2;
    else if(!strcmp("del", buff)) *s = 4;
    else if(!strcmp("quit", buff)) return 0;
    return sendData(buff, numbytes);
}

int s1_get(int *s) {
    rewind(fp);
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        u_char ks = dict.keysize;
        dict.key[ks] = 0;
        printf("[%s] Look key: (%d)%s\n", buff, ks, dict.key);
        if(!strcmp(buff, dict.key)) {
            *s = 0;
            return sendData(dict.data, dict.datasize);
        }
    }
    *s = 0;
    return sendData("null", 4);
}

#define copyKey() {\
    dict.keysize = (numbytes >= 255)?255:numbytes;\
    strncpy(dict.key, buff, 255);\
}

int s2_set(int *s) {
    rewind(fp);
    *s = 3;
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        u_char ks = dict.keysize;
        dict.key[ks] = 0;
        printf("[%ld] Key size: %d\n", numbytes, ks);
        if(!dict.keysize || !strcmp(buff, dict.key)) {
            copyKey();
            fseek(fp, -DICTBLKSZ, SEEK_CUR);
            return sendData("data", 4);
        }
    }
    copyKey();
    fseek(fp, 0, SEEK_END);
    return sendData("data", 4);
}

int s3_setData(int *s) {
    dict.datasize = (numbytes >= 255)?255:numbytes;
    memcpy(dict.data, buff, dict.datasize);
    *s = 0;
    if(fwrite(&dict, DICTBLKSZ, 1, fp) != 1) {
        fprintf(stderr, "Error set data: dict[%s]=%s\n", dict.key, buff);
        return sendData("erro", 4);
    } else {
        printf("Set data: dict[%s]=%s\n", dict.key, buff);
        fflush(fp);
        return sendData("succ", 4);
    }
}

int s4_del(int *s) {
    rewind(fp);
    *s = 0;
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        dict.key[dict.keysize] = 0;
        if(!strcmp(buff, dict.key)) {
            fseek(fp, -DICTBLKSZ+255, SEEK_CUR);
            fputc(0, fp);
            return sendData("succ", 4);
        }
    }
    return sendData("null", 4);
}

int checkBuffer() {
    static int s = 0;
    printf("Status: %d\n", s);
    switch(s) {
        case 0: return s0_init(&s); break;
        case 1: return s1_get(&s); break;
        case 2: return s2_set(&s); break;
        case 3: return s3_setData(&s); break;
        case 4: return s4_del(&s); break;
        default: return -1; break;
    }
}

void acceptClient() {
    puts("Ready for accept, waitting...");
    accept_fd = accept(fd, (struct sockaddr *)&client_addr, &struct_len);
    if(accept_fd > 0) {
        puts("Connected to the client.");
        sendData("Welcome to simple dict server.", 31);
        while((numbytes = recv(accept_fd, buff, BUFSIZ, 0)) > 0) {
            buff[numbytes] = 0;
            printf("Get %ld bytes: %s\n", numbytes, buff);
            puts("Check buffer");
            if(!checkBuffer()) break;
        }
        fprintf(stderr, "Recv %ld bytes\n", numbytes);
        close(accept_fd);
    } else perror("Error accepting client");
}

int main(int argc, char *argv[]) {
    if(argc != 4) showUsage(argv[0]);
    else {
        int port = 0;
        sscanf(argv[1], "%d", &port);
        if(port > 0 && port < 65536) {
            int times = 0;
            sscanf(argv[2], "%d", &times);
            if(times > 0) {
                fp = NULL;
                fp = fopen(argv[3], "rb+");
                if(!fp) fp = fopen(argv[3], "wb+");
                if(fp) {
                    if(bindServer(port, times)) if(listenSocket(times)) while(1) acceptClient();
                } else fprintf(stderr, "Error opening dict file: %s\n", argv[3]);
            } else fprintf(stderr, "Error times: %d\n", times);
        } else fprintf(stderr, "Error port: %d\n", port);
    }
    close(fd);
    exit(EXIT_FAILURE);
}
