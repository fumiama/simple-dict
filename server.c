#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define PASSWORD "fumiama"

int fd;
ssize_t numbytes;
socklen_t struct_len = sizeof(struct sockaddr_in);
struct sockaddr_in server_addr;
struct sockaddr_in client_addr;
char buff[BUFSIZ];
char *file_path;
pthread_t accept_threads[8];
FILE *fp_cross;

#define MAXWAITSEC 10
struct THREADTIMER {
    pthread_t *thread;
    time_t touch;
    int accept_fd;
};
typedef struct THREADTIMER THREADTIMER;

#define DATASIZE 64
struct DICTBLK{
    char key[(DATASIZE-1)];
    u_char keysize;
    char data[(DATASIZE-1)];
    u_char datasize;
};
typedef struct DICTBLK DICTBLK;
#define DICTBLKSZ sizeof(DICTBLK)
DICTBLK dict;

#define showUsage(program) printf("Usage: %s [-d] listen_port try_times dict_file\n\t-d: As daemon\n", program)

void acceptClient();
void acceptTimer(void *p);
int bindServer(uint16_t port, u_int try_times);
int checkBuffer(int accept_fd, int *s);
int closeDict(FILE *fp);
off_t fileSize(const char* fname);
void handleAccept(void *accept_fd_p);
void handle_quit(int signo);
int listenSocket(u_int try_times);
FILE *openDict(int lock_type);
int sendAll(int accept_fd);
int sendData(int accept_fd, char *data, size_t length);
int sm1_pwd(int *s, int accept_fd);
int s0_init(int *s, int accept_fd);
int s1_get(int *s, int accept_fd);
int s2_set(int *s, int accept_fd);
int s3_setData(int *s, int accept_fd);
int s4_del(int *s, int accept_fd);
int s5_list(int *s, int accept_fd);

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

int sendData(int accept_fd, char *data, size_t length) {
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

int sendAll(int accept_fd) {
    int re = 1;
    FILE *fp = openDict(LOCK_SH);
    //rewind(fp);
    sprintf(buff, "%zd", fileSize(file_path));
    re = sendData(accept_fd, buff, strlen(buff));
    while((numbytes = fread(buff, 1, BUFSIZ, fp)) > 0) {
        re = sendData(accept_fd, buff, numbytes);
    }
    closeDict(fp);
    return re;
}

int sm1_pwd(int *s, int accept_fd) {
    if(!strcmp(PASSWORD, buff)) *s = 0;
    return !*s;
}

int s0_init(int *s, int accept_fd) {
    if(!strcmp("get", buff)) *s = 1;
    else if(!strcmp("set", buff)) *s = 2;
    else if(!strcmp("del", buff)) *s = 4;
    else if(!strcmp("lst", buff)) *s = 5;
    else if(!strcmp("cat", buff)) return sendAll(accept_fd);
    else if(!strcmp("quit", buff)) return 0;
    return sendData(accept_fd, buff, numbytes);
}

int s1_get(int *s, int accept_fd) {
    FILE *fp = openDict(LOCK_SH);
    //rewind(fp);
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        u_char ks = dict.keysize;
        dict.key[ks] = 0;
        printf("[%s] Look key: (%d)%s\n", buff, ks, dict.key);
        if(!strcmp(buff, dict.key)) {
            *s = 0;
            return sendData(accept_fd, dict.data, dict.datasize);
        }
    }
    *s = 0;
    closeDict(fp);
    return sendData(accept_fd, "null", 4);
}

#define copyKey() {\
    dict.keysize = (numbytes >= (DATASIZE-1))?(DATASIZE-1):numbytes;\
    strncpy(dict.key, buff, (DATASIZE-1));\
}

int s2_set(int *s, int accept_fd) {
    FILE *fp = openDict(LOCK_EX);
    //rewind(fp);
    *s = 3;
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        u_char ks = dict.keysize;
        dict.key[ks] = 0;
        printf("[%zd] Key size: %d\n", numbytes, ks);
        if(!dict.keysize || !strcmp(buff, dict.key)) {
            copyKey();
            fseek(fp, -DICTBLKSZ, SEEK_CUR);
            return sendData(accept_fd, "data", 4);
        }
    }
    copyKey();
    fseek(fp, 0, SEEK_END);
    fp_cross = fp;
    return sendData(accept_fd, "data", 4);
}

int s3_setData(int *s, int accept_fd) {
    dict.datasize = (numbytes >= (DATASIZE-1))?(DATASIZE-1):numbytes;
    memcpy(dict.data, buff, dict.datasize);
    *s = 0;
    if(fwrite(&dict, DICTBLKSZ, 1, fp_cross) != 1) {
        fprintf(stderr, "Error set data: dict[%s]=%s\n", dict.key, buff);
        closeDict(fp_cross);
        return sendData(accept_fd, "erro", 4);
    } else {
        printf("Set data: dict[%s]=%s\n", dict.key, buff);
        //fflush(fp_cross);
        closeDict(fp_cross);
        return sendData(accept_fd, "succ", 4);
    }
}

int s4_del(int *s, int accept_fd) {
    FILE *fp = openDict(LOCK_EX);
    //rewind(fp);
    *s = 0;
    while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
        dict.key[dict.keysize] = 0;
        if(!strcmp(buff, dict.key)) {
            fseek(fp, -DICTBLKSZ+(DATASIZE-1), SEEK_CUR);
            fputc(0, fp);
            return sendData(accept_fd, "succ", 4);
        }
    }
    closeDict(fp);
    return sendData(accept_fd, "null", 4);
}

off_t fileSize(const char* fname) {
    struct stat statbuf;
    if(stat(fname, &statbuf)==0) return statbuf.st_size;
    else return -1;
}

int s5_list(int *s, int accept_fd) {
    *s = 0;
    off_t size = fileSize(file_path) / DICTBLKSZ;
    char *keys = calloc(size, DATASIZE);
    if(keys) {
        FILE *fp = openDict(LOCK_SH);
        //rewind(fp);
        keys[0] = 0;
        while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
            u_char ks = dict.keysize;
            dict.key[ks] = 0;
            printf("[%s] Look key: (%d)%s\n", buff, ks, dict.key);
            if(strstr(dict.key, buff)) {
                strcat(keys, dict.key);
                strcat(keys, "\n");
            }
        }
        int len = strlen(keys);
        closeDict(fp);
        if(len > 0) return sendData(accept_fd, keys, len);
        else return sendData(accept_fd, "null", 4);
    } else return sendData(accept_fd, "erro", 4);
}

int checkBuffer(int accept_fd, int *s) {
    printf("Status: %d\n", *s);
    switch(*s) {
        case -1: return sm1_pwd(s, accept_fd); break;
        case 0: return s0_init(s, accept_fd); break;
        case 1: return s1_get(s, accept_fd); break;
        case 2: return s2_set(s, accept_fd); break;
        case 3: return s3_setData(s, accept_fd); break;
        case 4: return s4_del(s, accept_fd); break;
        case 5: return s5_list(s, accept_fd); break;
        default: return -1; break;
    }
}

void handle_quit(int signo) {
    printf("Handle sig %d\n", signo);
    pthread_exit(NULL);
}

void acceptTimer(void *p) {
    THREADTIMER *timer = (THREADTIMER*)p;
    while(*timer->thread && !pthread_kill(*timer->thread, 0)) {
        sleep(MAXWAITSEC);
        puts("Check accept status");
        if(time(NULL) - timer->touch > MAXWAITSEC) {
            pthread_kill(*timer->thread, SIGQUIT);
            close(timer->accept_fd);
            *timer->thread = 0;
        }
    }
    free(p);
}

#define touchTimer(x) ((THREADTIMER*)(x))->touch = time(NULL)

void handleAccept(void *p) {
    int accept_fd = ((THREADTIMER*)p)->accept_fd;
    if(accept_fd > 0) {
        puts("Connected to the client.");
        signal(SIGQUIT, handle_quit);
        pthread_t thread;
        if (pthread_create(&thread, NULL, (void *)&acceptTimer, p)) perror("Error creating timer thread");
        else puts("Creating timer thread succeeded");
        sendData(accept_fd, "Welcome to simple dict server.", 31);
        int s = -1;
        while(*((THREADTIMER*)p)->thread && (numbytes = recv(accept_fd, buff, BUFSIZ, 0)) > 0) {
            touchTimer(p);
            buff[numbytes] = 0;
            printf("Get %zd bytes: %s\n", numbytes, buff);
            puts("Check buffer");
            if(!checkBuffer(accept_fd, &s)) break;
        }
        printf("Recv %zd bytes\n", numbytes);
        close(accept_fd);
    } else perror("Error accepting client");
}

void acceptClient() {
    while(1) {
        puts("Ready for accept, waitting...");
        int p = 0;
        while(p < 8 && accept_threads[p] && !pthread_kill(accept_threads[p], 0)) p++;
        if(p < 8) {
            printf("Run on thread No.%d\n", p);
            THREADTIMER *timer = malloc(sizeof(THREADTIMER));
            timer->accept_fd = accept(fd, (struct sockaddr *)&client_addr, &struct_len);
            timer->thread = &accept_threads[p];
            timer->touch = time(NULL);
            if (pthread_create(timer->thread, NULL, (void *)&handleAccept, timer)) perror("Error creating thread");
            else puts("Creating thread succeeded");
        } else {
            puts("Max thread cnt exceeded");
            sleep(1);
        }
    }
}

FILE *openDict(int lock_type) {
    FILE *fp = NULL;
    fp = fopen(file_path, "rb+");
    if(fp) flock(fileno(fp), lock_type);
    return fp;
}

int closeDict(FILE *fp) {
    if(fp) flock(fileno(fp), LOCK_UN);
    return fclose(fp);
}

int main(int argc, char *argv[]) {
    if(argc != 4 && argc != 5) showUsage(argv[0]);
    else {
        int port = 0;
        int as_daemon = !strcmp("-d", argv[1]);
        sscanf(argv[as_daemon?2:1], "%d", &port);
        if(port > 0 && port < 65536) {
            int times = 0;
            sscanf(argv[as_daemon?3:2], "%d", &times);
            if(times > 0) {
                if(!as_daemon || (as_daemon && (daemon(1, 1) >= 0))) {
                    FILE *fp = NULL;
                    fp = fopen(argv[as_daemon?4:3], "rb+");
                    if(!fp) fp = fopen(argv[as_daemon?4:3], "wb+");
                    if(fp) {
                        file_path = argv[as_daemon?4:3];
                        fclose(fp);
                        if(bindServer(port, times)) if(listenSocket(times)) acceptClient();
                    } else fprintf(stderr, "Error opening dict file: %s\n", argv[as_daemon?4:3]);
                } else perror("Start daemon error");
            } else fprintf(stderr, "Error times: %d\n", times);
        } else fprintf(stderr, "Error port: %d\n", port);
    }
    close(fd);
    exit(EXIT_FAILURE);
}
