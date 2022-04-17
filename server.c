/* See feature_test_macros(7) */
#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <simple_protobuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "server.h"
#include "dict.h"
#include "crypto.h"
#include "config.h"

#if !__APPLE__
    #include <sys/sendfile.h>
#endif

#ifdef LISTEN_ON_IPV6
    static socklen_t struct_len = sizeof(struct sockaddr_in6);
    static struct sockaddr_in6 server_addr;
#else
    static socklen_t struct_len = sizeof(struct sockaddr_in);
    static struct sockaddr_in server_addr;
#endif

struct THREADTIMER {
    uint32_t index;
    uint32_t lock_type;
    int accept_fd;
    char *dat, *ptr;
    time_t touch;
    ssize_t numbytes;
};
typedef struct THREADTIMER THREADTIMER;
static THREADTIMER timers[THREADCNT];
#define timer_pointer_of(x) ((THREADTIMER*)(x))
#define touch_timer(x) (timer_pointer_of(x)->touch = time(NULL))

static int fd;      // server fd
static pthread_t accept_threads[THREADCNT];
static DICT d;
static DICT* setdict;
static uint32_t* items_len;
static CONFIG cfg;
static pthread_attr_t attr;
static pthread_rwlock_t mu;

#define DICTPOOLSZ (((uint32_t)-1)>>((sizeof(uint32_t)*8-DICTPOOLBIT)))
static DICT* dict_pool[DICTPOOLSZ+1];

static void accept_client();
static void accept_timer(void *p);
static uint16_t bind_server(uint16_t port);
static int close_and_send(THREADTIMER* timer, enum SERVERACK cmd, char *data, size_t numbytes);
static enum SERVERACK del(FILE *fp, char* key, int len, char ret[4]);
static void handle_accept(void *accept_fd_p);
static void handle_int(int signo);
static void handle_pipe(int signo);
static void handle_quit(int signo);
static void init_dict_pool(FILE *fp);
static void kill_thread(THREADTIMER* timer);
static uint32_t last_nonnull(char* p, uint32_t max_size);
static int listen_socket();
static int send_all(THREADTIMER *timer);
static int send_data(int accept_fd, int index, enum SERVERACK cmd, char *data, size_t length);
static int s1_get(THREADTIMER *timer);
static int s2_set(THREADTIMER *timer);
static int s3_set_data(THREADTIMER *timer);
static int s4_del(THREADTIMER *timer);
static int s5_md5(THREADTIMER *timer);

static uint16_t bind_server(uint16_t port) {
    #ifdef LISTEN_ON_IPV6
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(port);
        bzero(&(server_addr.sin6_addr), sizeof(server_addr.sin6_addr));
        fd = socket(PF_INET6, SOCK_STREAM, 0);
    #else
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        bzero(&(server_addr.sin_zero), 8);
        fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif
    if(!~bind(fd, (struct sockaddr *)&server_addr, struct_len)) {
        perror("Bind server failure: ");
        return 0;
    }
    #ifdef LISTEN_ON_IPV6
        port = ntohs(server_addr.sin6_port);
        struct in6_addr in = server_addr.sin6_addr;
        char str[INET6_ADDRSTRLEN];	// 46
        inet_ntop(AF_INET6, &in, str, sizeof(str));
    #else
        port = ntohs(server_addr.sin_port);
        struct in_addr in = server_addr.sin_addr;
        char str[INET_ADDRSTRLEN];	// 16
        inet_ntop(AF_INET, &in, str, sizeof(str));
    #endif
    printf("Bind server successfully on %s:%u\n", str, port);
    return port;
}

static int listen_socket() {
    if(!~listen(fd, THREADCNT)) {
        perror("Listen failed: ");
        return 0;
    }
    puts("Listening...");
    return 1;
}

static uint32_t last_nonnull(char* p, uint32_t max_size) {
    if(max_size > 1) while(!p[max_size - 1]) max_size--;
    return max_size;
}

static int send_data(int accept_fd, int index, enum SERVERACK cmd, char *data, size_t length) {
    char buf[CMDPACKET_LEN_MAX];
    CMDPACKET* p = (CMDPACKET*)buf;
    p->cmd = (uint8_t)cmd;
    p->datalen = length;
    memcpy(p->data, data, p->datalen);
    cmdpacket_encrypt(p, index, cfg.pwd);
    int total = CMDPACKET_HEAD_LEN+p->datalen;
    if(!~send(accept_fd, buf, total, 0)) {
        perror("Send data error: ");
        return 0;
    } else {
        printf("Send %d bytes data: ", total);
        for(int i = 0; i < length; i++) putchar(data[i]);
        putchar('\n');
        return 1;
    }
}

static int send_all(THREADTIMER *timer) {
    int re = 1;
    FILE *fp = open_dict(DICT_LOCK_SH, timer->index, &mu);
    if(!fp) return 1;
    pthread_cleanup_push((void*)&pthread_rwlock_unlock, (void*)&mu);
    timer->lock_type = DICT_LOCK_SH;
    off_t len = 0, file_size = get_dict_size();
    char* buf = (char*)malloc(file_size);
    if(buf) {
        pthread_cleanup_push((void*)&free, (void*)&buf);
        if(fread(buf, file_size, 1, fp) == 1) {
            #ifdef DEBUG
                printf("Get dict file size: %u\n", (unsigned int)file_size);
            #endif
            char* encbuf = raw_encrypt(buf, &file_size, timer->index, cfg.pwd);
            sprintf(timer->dat, "%u$", (unsigned int)file_size);
            //printf("Get encrypted file size: %s\n", timer->dat);
            //FILE* fp = fopen("raw_after_enc", "wb+");
            //fwrite(encbuf, file_size, 1, fp);
            //fclose(fp);
            pthread_cleanup_push((void*)&free, (void*)&encbuf);
            if(send(timer->accept_fd, timer->dat, strlen(timer->dat), 0) > 0) {
                re = send(timer->accept_fd, encbuf, file_size, 0);
                printf("Send %u bytes.\n", re);
            } else re = 0;
            pthread_cleanup_pop(1);
        }
        pthread_cleanup_pop(1);
    }
    close_dict(DICT_LOCK_SH, timer->index, &mu);
    timer->lock_type = DICT_LOCK_UN;
    pthread_cleanup_pop(0);
    return re;
}

#define has_next(fp, ch) ((ch=getc(fp)),(feof(fp)?0:(ch?ungetc(ch,fp):1)))

static void init_dict_pool(FILE *fp) {
    uint8_t digest[16];
    int ch;
    while(has_next(fp, ch)) {
        if(!ch) continue; // skip null bytes
        SIMPLE_PB* spb = get_pb(fp);
        if(!spb) continue; // skip error bytes
        DICT* d = (DICT*)spb->target;
        md5((uint8_t *)d->key, strlen(d->key)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        int c = 16-4;
        DICT* slot;

        while((slot=dict_pool[p]) && c-->0) {
            #ifdef DEBUG
                printf("digest of %s: %08x got conflicted, remaining chance: %d.\n", d->key, p, c);
            #endif
            p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
            #ifdef DEBUG
                printf("skip digest of %s to %08x.\n", d->key, p);
            #endif
        }
        #ifdef DEBUG
            if(slot) printf("cannot find any empty slot for digest of %s: %08x, drop it.\n", d->key, p);
        #endif

        if(!slot) {
            DICT* dnew = (DICT*)malloc(sizeof(DICT));
            memcpy(dnew, d, sizeof(DICT));
            dict_pool[p] = dnew; // 解决哈希冲突
        }

        free(spb);
    }
}

static int s1_get(THREADTIMER *timer) {
    uint8_t digest[16];
    FILE *fp = open_dict(DICT_LOCK_SH, timer->index, &mu);
    //timer->status = 0;
    while(fp) {
        int ch;
        timer->lock_type = DICT_LOCK_SH;
        md5((uint8_t*)timer->dat, strlen(timer->dat)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        if(!dict_pool[p]) break;

        int c = 16-4;
        int notok = 1;
        while(dict_pool[p] && (notok=strcmp(timer->dat, dict_pool[p]->key)) && c-->0) p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
        if(!notok) {
            return close_and_send(timer, ACKSUCC, dict_pool[p]->data, last_nonnull(dict_pool[p]->data, DICTDATSZ));
        }

        while(has_next(fp, ch)) {
            if(!ch) continue; // skip null bytes
            SIMPLE_PB* spb = get_pb(fp);
            DICT* d = (DICT*)spb->target;
            if(!strcmp(timer->dat, d->key)) {
                int r;
                pthread_cleanup_push((void*)free, (void*)spb);
                r = close_and_send(timer, ACKSUCC, d->data, last_nonnull(d->data, DICTDATSZ));
                pthread_cleanup_pop(1);
                return r;
            } else free(spb);
        }

        break;
    }
    return close_and_send(timer, ACKNULL, "null", 4);
}

static int s2_set(THREADTIMER *timer) {
    uint8_t digest[16];
    timer->lock_type = DICT_LOCKING_EX;
    FILE *fp = open_dict(DICT_LOCK_EX, timer->index, &mu);
    if(fp) {
        touch_timer(timer);
        timer->lock_type = DICT_LOCK_EX;
        md5((uint8_t*)timer->dat, strlen(timer->dat)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;

        if(!dict_pool[p]) setdict = dict_pool[p] = (DICT*)malloc(sizeof(DICT));
        else {
            int c = 16-4;
            int notok;
            while(dict_pool[p] && (notok=strcmp(timer->dat, dict_pool[p]->key)) && c-->0) p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
            if(!dict_pool[p]) setdict = dict_pool[p] = (DICT*)malloc(sizeof(DICT)); // 无值
            else if(notok) setdict = &d; // 全部冲突
            else { // 已有值
                char ret[4];
                // 先删去
                if(del(fp, timer->dat, timer->numbytes+1, ret) == ACKERRO) return close_and_send(timer, ACKERRO, "erro", 4);
                setdict = dict_pool[p];
            }
        }
        #ifdef DEBUG
            printf("item %s(%0*x) will fill into %p.\n", timer->dat, DICTPOOLBIT/4, p, dict_pool[p]);
        #endif

        //timer->status = 3;
        memset(setdict, 0, sizeof(DICT));
        strncpy(setdict->key, timer->dat, DICTKEYSZ-1);
        fseek(fp, 0, SEEK_END);
        return send_data(timer->accept_fd, timer->index, ACKDATA, "data", 4);
    } else {
        timer->lock_type = DICT_LOCK_UN;
        //timer->status = 0;
        return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    }
}

static int s3_set_data(THREADTIMER *timer) {
    //timer->status = 0;
    uint32_t datasize = (timer->numbytes > (DICTDATSZ-1))?(DICTDATSZ-1):timer->numbytes;
    #ifdef DEBUG
        printf("Set data size: %u\n", datasize);
    #endif
    memcpy(setdict->data, timer->dat, datasize);

    if(!set_pb(get_dict_fp_wr(), items_len, sizeof(DICT), setdict)) {
        fprintf(stderr, "Error set data: dict[%s]=%s\n", setdict->key, timer->dat);
        return close_and_send(timer, ACKERRO, "erro", 4);
    } else {
        printf("Set data: dict[%s]=%s\n", setdict->key, timer->dat);
        return close_and_send(timer, ACKSUCC, "succ", 4);
    }
}

static enum SERVERACK del(FILE *fp, char* key, int len, char ret[4]) {
    int ch;
    while(has_next(fp, ch)) {
        if(!ch) continue; // skip null bytes
        SIMPLE_PB* spb = get_pb(fp);
        DICT* d = (DICT*)spb->target;
        if(memcmp(key, d->key, len)) {
            free(spb);
            continue;
        }
        uint32_t next = ftell(fp);
        uint32_t this = next - spb->real_len;
        fseek(fp, 0, SEEK_END);
        uint32_t end = ftell(fp);
        if(next == end) {
            if(!ftruncate(fileno(fp), end - spb->real_len)) {
                free(spb);
                *(uint32_t*)ret = *(uint32_t*)"succ";
                return ACKSUCC;
            }
            free(spb);
            *(uint32_t*)ret = *(uint32_t*)"erro";
            return ACKERRO;
        }
        uint32_t cap = end - next;
        #ifdef DEBUG
            printf("this: %u, next: %u, end: %u, cap: %u\n", this, next, end, cap);
        #endif
        char* data = malloc(cap);
        if(data) {
            fseek(fp, next, SEEK_SET);
            if(fread(data, cap, 1, fp) == 1) {
                if(!ftruncate(fileno(fp), end - spb->real_len)) {
                    fseek(fp, this, SEEK_SET);
                    if(fwrite(data, cap, 1, fp) == 1) {
                        free(data);
                        free(spb);
                        *(uint32_t*)ret = *(uint32_t*)"succ";
                        return ACKSUCC;
                    }
                }
            }
            free(data);
        }
        free(spb);
        *(uint32_t*)ret = *(uint32_t*)"erro";
        return ACKERRO;
    }
    *(uint32_t*)ret = *(uint32_t*)"null";
    return ACKNULL;
}

static int s4_del(THREADTIMER *timer) {
    uint8_t digest[16];
    char ret[4];
    timer->lock_type = DICT_LOCK_EX;
    FILE *fp = open_dict(DICT_LOCK_EX, timer->index, &mu);
    //timer->status = 0;
    if(fp) {
        md5((uint8_t*)timer->dat, strlen(timer->dat)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        int c = 16-4;
        int notok = 1;
        while(dict_pool[p] && (notok=strcmp(timer->dat, dict_pool[p]->key)) && c-->0) p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
        if(notok) return close_and_send(timer, ACKNULL, "null", 4);
        free(dict_pool[p]);
        dict_pool[p] = NULL;
        return close_and_send(timer, del(fp, timer->dat, timer->numbytes+1, ret), ret, 4);
    }
    return close_and_send(timer, ACKNULL, "null", 4);
}

static int s5_md5(THREADTIMER *timer) {
    //timer->status = 0;
    fill_md5(&mu);
    if(is_md5_equal((uint8_t*)timer->dat)) return send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4);
    else return send_data(timer->accept_fd, timer->index, ACKNEQU, "nequ", 4);
}

static void handle_quit(int signo) {
    printf("Handle quit with sig %d\n", signo);
    pthread_exit(NULL);
}

static void accept_timer(void *p) {
    THREADTIMER *timer = timer_pointer_of(p);
    uint32_t index = timer->index;
    while(accept_threads[index] && !pthread_kill(accept_threads[index], 0)) {
        sleep(MAXWAITSEC / 4);
        time_t waitsec = time(NULL) - timer->touch;
        printf("Wait sec: %u, max: %u\n", (unsigned int)waitsec, MAXWAITSEC);
        if(timer->lock_type >= DICT_LOCK_EX) {
            if(waitsec > MAXWAITSEC*THREADCNT) break;
        } else if(waitsec > MAXWAITSEC) break;
    }
    pthread_t thread = accept_threads[index];
    if(thread) {
        pthread_kill(thread, SIGQUIT);
        puts("Kill thread");
    }
}

static void kill_thread(THREADTIMER* timer) {
    puts("Start killing");
    accept_threads[timer->index] = 0;
    if(timer->accept_fd) {
        close(timer->accept_fd);
        timer->accept_fd = 0;
        puts("Close accept");
    }
    if(timer->ptr) {
        free(timer->ptr);
        timer->ptr = NULL;
        puts("Free data");
    }
    if(timer->lock_type) close_dict(timer->lock_type, timer->index, &mu);
    puts("Finish killing");
}

static void handle_int(int signo) {
    puts("Keyboard interrupted");
    exit(0);
}

static void handle_pipe(int signo) {
    fprintf(stderr, "Pipe error: %d\n", signo);
    pthread_exit(NULL);
}

static void handle_accept(void *p) {
    puts("\nConnected to the client, handling accept...");
    pthread_t thread;
    if (pthread_create(&thread, &attr, (void *)&accept_timer, p)) {
        perror("Error creating timer thread: ");
        kill_thread(timer_pointer_of(p));
        return;
    }
    puts("Creating timer thread succeeded");
    pthread_cleanup_push((void*)&kill_thread, p);
    int accept_fd = timer_pointer_of(p)->accept_fd;
    uint32_t index = timer_pointer_of(p)->index;
    char *buff = malloc(BUFSIZ*sizeof(char));
    if(buff) {
        timer_pointer_of(p)->ptr = buff;
        CMDPACKET* cp = (CMDPACKET*)buff;
        ssize_t numbytes = 0, offset = 0;
        while(
                accept_threads[index]
                && (
                    offset >= CMDPACKET_HEAD_LEN
                    || (numbytes = recv(accept_fd, buff+offset, CMDPACKET_HEAD_LEN-offset, MSG_WAITALL)) > 0
                )
            ) {
            touch_timer(p);
            offset += numbytes;
            #ifdef DEBUG
                printf("[handle] Get %zd bytes, total: %zd.\n", numbytes, offset);
            #endif
            if(offset < CMDPACKET_HEAD_LEN) break;
            if(offset < CMDPACKET_HEAD_LEN+cp->datalen) {
                numbytes = recv(accept_fd, buff+offset, CMDPACKET_HEAD_LEN+cp->datalen-offset, MSG_WAITALL);
                if(numbytes <= 0) break;
                else {
                    offset += numbytes;
                    #ifdef DEBUG
                        printf("[handle] Get %zd bytes, total: %zd.\n", numbytes, offset);
                    #endif
                }
            }
            numbytes = CMDPACKET_HEAD_LEN+cp->datalen; // 暂存 packet len
            if(offset < numbytes) break;
            #ifdef DEBUG
                printf("[handle] Decrypt %d bytes data...\n", (int)cp->datalen);
            #endif
            if(cp->cmd < 5) {
                if(cmdpacket_decrypt(cp, index, cfg.pwd)) {
                    cp->data[cp->datalen] = 0;
                    timer_pointer_of(p)->dat = (char*)cp->data;
                    timer_pointer_of(p)->numbytes = cp->datalen;
                    printf("[normal] Get %zd bytes packet with cmd: %d, data: %s\n", offset, cp->cmd, cp->data);
                    switch(cp->cmd) {
                        case CMDGET:
                            //timer_pointer_of(p)->status = 1;
                            if(!s1_get(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDCAT:
                            if(!send_all(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDMD5:
                            //timer_pointer_of(p)->status = 5;
                            if(!s5_md5(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDACK: break;
                        case CMDEND:
                        default: goto CONV_END; break;
                    }
                } else {
                    puts("Decrypt normal data failed");
                    break;
                }
            } else if(cp->cmd < 8) {
                if(cmdpacket_decrypt(cp, index, cfg.sps)) {
                    cp->data[cp->datalen] = 0;
                    timer_pointer_of(p)->dat = (char*)cp->data;
                    timer_pointer_of(p)->numbytes = cp->datalen;
                    printf("[super] Get %zd bytes packet with data: %s\n", offset, cp->data);
                    switch(cp->cmd) {
                        case CMDSET:
                            //timer_pointer_of(p)->status = 2;
                            if(!s2_set(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDDEL:
                            //timer_pointer_of(p)->status = 4;
                            if(!s4_del(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDDAT:
                            if(timer_pointer_of(p)->lock_type == DICT_LOCK_EX) {
                                if(!s3_set_data(timer_pointer_of(p))) goto CONV_END;
                            }
                        break;
                        default: goto CONV_END; break;
                    }
                } else {
                    puts("Decrypt super data failed");
                    break;
                }
            } else {
                puts("Invalid command");
                break;
            }
            if(offset > numbytes) {
                offset -= numbytes;
                memmove(buff, buff+numbytes, offset);
                numbytes = 0;
            } else offset = 0;
            #ifdef DEBUG
                printf("Offset after analyzing packet: %zd\n", offset);
            #endif
        }
        CONV_END: puts("Conversation end");
    } else perror("Error allocating buffer: ");
    pthread_cleanup_pop(1);
    puts("Thread exited normally");
}

static void accept_client() {
    pid_t pid = fork();
    while (pid > 0) {      //主进程监控子进程状态，如果子进程异常终止则重启之
        wait(NULL);
        puts("Server subprocess exited. Restart...");
        pid = fork();
    }
    while(pid < 0) {
        perror("Error when forking a subprocess: ");
        sleep(1);
    }
    signal(SIGINT,  handle_int);
    signal(SIGQUIT, handle_quit);
    signal(SIGPIPE, handle_pipe);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    init_crypto();
    init_dict_pool(get_dict_fp_rd());
    while(1) {
        puts("Ready for accept, waitting...");
        int p = 0;
        while(p < THREADCNT && accept_threads[p] && !pthread_kill(accept_threads[p], 0)) p++;
        if(p >= THREADCNT) {
            puts("Max thread cnt exceeded");
            sleep(1);
            continue;
        }
        printf("Thread slot is empty at No.%d\n", p);
        #ifdef LISTEN_ON_IPV6
            struct sockaddr_in6 client_addr;
        #else
            struct sockaddr_in client_addr;
        #endif
        int accept_fd;
        while((accept_fd=accept(fd, (struct sockaddr *)&client_addr, &struct_len))<=0)
            perror("Accept client error: ");
        #ifdef LISTEN_ON_IPV6
            uint16_t port = ntohs(client_addr.sin6_port);
            struct in6_addr in = client_addr.sin6_addr;
            char str[INET6_ADDRSTRLEN];	// 46
            inet_ntop(AF_INET6, &in, str, sizeof(str));
        #else
            uint16_t port = ntohs(client_addr.sin_port);
            struct in_addr in = client_addr.sin_addr;
            char str[INET_ADDRSTRLEN];	// 16
            inet_ntop(AF_INET, &in, str, sizeof(str));
        #endif
        printf("Accept client %s:%u\n", str, port);
        THREADTIMER* timer = &timers[p];
        timer->accept_fd = accept_fd;
        timer->index = p;
        timer->touch = time(NULL);
        timer->ptr = NULL;
        reset_seq(p);
        if (pthread_create(accept_threads + p, &attr, (void *)&handle_accept, timer)) {
            perror("Error creating thread: ");
            kill_thread(timer);
            continue;
        }
        puts("Creating thread succeeded");
    }
}

static int close_and_send(THREADTIMER* timer, enum SERVERACK cmd, char *data, size_t numbytes) {
    close_dict(timer->lock_type, timer->index, &mu);
    timer->lock_type = DICT_LOCK_UN;
    return send_data(timer->accept_fd, timer->index, cmd, data, numbytes);
}

#define argequ(i, arg) (*(uint16_t*)argv[i] == *(uint16_t*)(arg))
#define showUsage(program) \
    printf("Usage:\n%s [-d] listen_port dict_file [config_file | -]\n\t-d: As daemon\n\t- : Read config from env SDS_PWD & SDS_SPS\n", program)
int main(int argc, char *argv[]) {
    if(argc != 4 && argc != 5) {
        showUsage(argv[0]);
        return 0;
    }
    int port = 0;
    int as_daemon = argequ(1, "-d");
    sscanf(argv[as_daemon?2:1], "%d", &port);
    if(port < 0 || port >= 65536) {
        fprintf(stderr, "Error port: %d\n", port);
        return 1;
    }
    if(as_daemon && daemon(1, 1)<0) {
        perror("Start daemon error: ");
        return 2;
    }
    FILE *fp = NULL;
    fp = fopen(argv[as_daemon?3:2], "rb+");
    if(!fp) fp = fopen(argv[as_daemon?3:2], "wb+");
    if(!fp) {
        fprintf(stderr, "Error opening dict file: %s : ", argv[as_daemon?3:2]);
        perror("");
        return 3;
    }
    fclose(fp);
    if(init_dict(argv[as_daemon?3:2], &mu))
        return 4;
    fp = NULL;
    if(argv[as_daemon?4:3][0] == '-') { // use env
        fp = (FILE*)1;
        puts("Read config from env");
        char* pwd = getenv("SDS_PWD");
        if(pwd) {
            char* sps = getenv("SDS_SPS");
            if(sps) {
                strncpy(cfg.pwd, pwd, 64);
                strncpy(cfg.sps, sps, 64);
                cfg.pwd[63] = 0;
                cfg.sps[63] = 0;
                fp = (FILE*)-1;
            } else {
                fputs("Env SDS_SPS is null", stderr);
                return 5;
            }
        } else {
            fputs("Env SDS_PWD is null", stderr);
            return 6;
        }
    }
    if(!fp) fp = fopen(argv[as_daemon?4:3], "rb");
    if(fp == NULL) {
        fprintf(stderr, "Error opening config file: %s : ", argv[as_daemon?4:3]);
        perror("");
        return 7;
    }
    if(~((int)fp)) {
        SIMPLE_PB* spb = get_pb(fp);
        cfg = *(CONFIG*)spb->target;
        fclose(fp);
        free(spb);
    }
    items_len = align_struct(sizeof(DICT), 2, d.key, d.data);
    if(!items_len) {
        fputs("Align struct error", stderr);
        return 8;
    }
    if(!bind_server((uint16_t)port)) return 9;
    if(!listen_socket()) return 10;
    accept_client();
    close(fd);
    return 11;
}
