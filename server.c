/* See feature_test_macros(7) */
#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <simple_protobuf.h>
#include <simplecrypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "server.h"
#include "dict.h"
#include "crypto.h"
#include "config.h"

#ifdef LISTEN_ON_IPV6
    static socklen_t struct_len = sizeof(struct sockaddr_in6);
    static struct sockaddr_in6 server_addr;
#else
    static socklen_t struct_len = sizeof(struct sockaddr_in);
    static struct sockaddr_in server_addr;
#endif

struct thread_timer_t {
    uint32_t index;
    int accept_fd;
    time_t touch;
    ssize_t numbytes;
    char *dat;
    pthread_t thread;
    pthread_t timerthread;
    pthread_cond_t c;
    pthread_mutex_t mc;
    pthread_cond_t tc;
    pthread_mutex_t tmc;
    pthread_rwlock_t mb;
    uint8_t isbusy;         // lock by mb
    uint8_t hastimerslept;  // lock by tmc
    uint8_t buf[BUFSIZ-sizeof(uint32_t)-sizeof(int)-sizeof(time_t)-sizeof(ssize_t)-sizeof(char*)-2*sizeof(pthread_t)-2*sizeof(pthread_cond_t)-2*sizeof(pthread_mutex_t)-sizeof(pthread_rwlock_t)-2*sizeof(uint8_t)];
};
typedef struct thread_timer_t thread_timer_t;
static thread_timer_t timers[THREADCNT];
#define timer_pointer_of(x) ((thread_timer_t*)(x))
#define touch_timer(x) (timer_pointer_of(x)->touch = time(NULL))

static dict_t setdicts[THREADCNT];
static uint32_t* items_len;
static config_t cfg;
static pthread_attr_t attr;

#define DICTPOOLSZ (((uint32_t)-1)>>((sizeof(uint32_t)*8-DICTPOOLBIT)))
static dict_t* dict_pool[DICTPOOLSZ+1];

static void accept_client(int fd);
static void accept_timer(void *p);
static int bind_server(uint16_t* port);
static void cleanup_thread(thread_timer_t* timer);
static server_ack_t del(FILE *fp, const char* key, int len, char ret[4]);
static void handle_accept(void *accept_fd_p);
static void handle_int(int signo);
static void handle_kill(int signo);
static void handle_pipe(int signo);
static void handle_quit(int signo);
static void handle_segv(int signo);
static void init_dict_pool(FILE *fp);
static int insert_item(FILE *fp, const dict_t* dict, int keysize, int datasize);
static inline uint32_t last_nonnull(const char* p, uint32_t max_size);
static int listen_socket(int fd);
static void process_defer();
static int send_all(thread_timer_t *timer);
static int send_data(int accept_fd, int index, server_ack_t cmd, const char *data, size_t length);
static int s1_get(thread_timer_t *timer);
static int s2_set(thread_timer_t *timer);
static int s3_set_data(thread_timer_t *timer);
static int s4_del(thread_timer_t *timer);
static int s5_md5(thread_timer_t *timer);

static int bind_server(uint16_t* port) {
    #ifdef LISTEN_ON_IPV6
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(*port);
        bzero(&(server_addr.sin6_addr), sizeof(server_addr.sin6_addr));
        int fd = socket(PF_INET6, SOCK_STREAM, 0);
    #else
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(*port);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        bzero(&(server_addr.sin_zero), 8);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif
    int on = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        perror("Set socket option failure");
        return 0;
    }
    if(!~bind(fd, (struct sockaddr *)&server_addr, struct_len)) {
        perror("Bind server failure");
        return 0;
    }
    #ifdef LISTEN_ON_IPV6
        *port = ntohs(server_addr.sin6_port);
        struct in6_addr in = server_addr.sin6_addr;
        char str[INET6_ADDRSTRLEN];	// 46
        inet_ntop(AF_INET6, &in, str, sizeof(str));
    #else
        *port = ntohs(server_addr.sin_port);
        struct in_addr in = server_addr.sin_addr;
        char str[INET_ADDRSTRLEN];	// 16
        inet_ntop(AF_INET, &in, str, sizeof(str));
    #endif
    printf("Bind server successfully on %s:%u\n", str, *port);
    return fd;
}

static int listen_socket(int fd) {
    if(!~listen(fd, THREADCNT)) {
        perror("Listen failed");
        return 0;
    }
    puts("Listening...");
    return fd;
}

static inline uint32_t last_nonnull(const char* p, uint32_t max_size) {
    if(max_size > 1) while(!p[max_size - 1]) max_size--;
    return max_size;
}

static int send_data(int accept_fd, int index, server_ack_t cmd, const char *data, size_t length) {
    char buf[CMDPACKET_LEN_MAX];
    if(length <= UINT8_MAX) {
        cmdpacket_t p = (cmdpacket_t)buf;
        p->cmd = (uint8_t)cmd;
        p->datalen = length;
        cmdpacket_encrypt(p, index, cfg.pwd, data);
        int total = CMDPACKET_HEAD_LEN+p->datalen;
        if(!~send(accept_fd, buf, total, 0)) {
            perror("Send data error");
            return 0;
        }
        printf("Send %d bytes data: ", total);
        for(int i = 0; i < length; i++) putchar(data[i]);
        putchar('\n');
        return 1;
    }
    fputs("Send data: length too long.", stderr);
    return 0;
}

static int send_all(thread_timer_t *timer) {
    int re = 1;
    FILE *fp = open_dict(timer->index, 1);
    if(fp == NULL) return 1;
    pthread_cleanup_push((void*)&close_dict, (void*)(uintptr_t)timer->index);
    off_t len = 0, file_size = get_dict_size();

    while(1) {
        if(file_size <= 0) {
            re = send(timer->accept_fd, "0$0123456789abcdef", CMDPACKET_HEAD_LEN, 0);
            puts("Send 0 bytes.");
            break;
        }
        char* buf = (char*)malloc(file_size);
        if(!buf) {
            perror("malloc");
            break;
        }
        pthread_cleanup_push((void*)&free, (void*)buf);
        if(fread(buf, file_size, 1, fp) == 1) {
            #ifdef DEBUG
                printf("Get dict file size: %u\n", (unsigned int)file_size);
            #endif
            char* encbuf = raw_encrypt(buf, &file_size, timer->index, cfg.pwd);
            sprintf(timer->dat, "%u$", (unsigned int)file_size);
            pthread_cleanup_push((void*)&free, (void*)encbuf);
            struct iovec iov[2] = {{timer->dat, strlen(timer->dat)}, {encbuf, file_size}};
            re = writev(timer->accept_fd, (const struct iovec *)&iov, 2);
            printf("Send %d bytes.\n", re);
            pthread_cleanup_pop(1);
        }
        pthread_cleanup_pop(1);
        break;
    }

    pthread_cleanup_pop(1);
    return re;
}

#define has_next(fp, ch) ((ch=getc(fp)),(feof(fp)?0:(ch?ungetc(ch,fp):1)))

static void init_dict_pool(FILE *fp) {
    uint8_t digest[16];
    uint8_t buf[8+DICTSZ];
    int ch;
    while(has_next(fp, ch)) {
        if(!ch) continue; // skip null bytes
        SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
        if(!spb) {
            fputs("Bad spb file", stderr);
            exit(EXIT_FAILURE);
        }
        dict_t* d = (dict_t*)spb->target;
        md5((uint8_t *)d->key, strlen(d->key)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        int c = 16-4;
        dict_t* slot;

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
            dict_t* dnew = (dict_t*)malloc(sizeof(dict_t));
            memcpy(dnew, d, sizeof(dict_t));
            dict_pool[p] = dnew; // 解决哈希冲突
        }
    }
}

static int s1_get(thread_timer_t *timer) {
    uint8_t digest[16];
    uint8_t buf[8+DICTSZ];
    if(require_shared_lock()) // busy
        return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    int ret = -1;

    pthread_cleanup_push((void*)&release_shared_lock, NULL);
    while(1) {
        md5((uint8_t*)timer->dat, strlen(timer->dat)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        if(!dict_pool[p]) {
            ret = send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4); // 无值
            break;
        }

        int c = 16-4;
        int notok = 1;
        while(dict_pool[p] && (notok=strcmp(timer->dat, dict_pool[p]->key)) && c-->0) {
            #ifdef DEBUG
                printf("digest of %s: %08x got conflicted, remaining chance: %d.\n", timer->dat, p, c);
            #endif
            p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
            #ifdef DEBUG
                printf("skip digest of %s to %08x.\n", timer->dat, p);
            #endif
        }
        if(!notok) { // 找到值
            ret = send_data(timer->accept_fd, timer->index, ACKSUCC, dict_pool[p]->data, last_nonnull(dict_pool[p]->data, DICTDATSZ));
            break;
        }
        if(!dict_pool[p]) {
            ret = send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4); // 无值
            break;
        }
        #ifdef DEBUG
            printf("cannot find any empty slot for digest of %s: %08x, open dict to find it.\n", timer->dat, p);
        #endif

        break;
    }
    pthread_cleanup_pop(1);
    if(~ret) return ret;

    FILE *fp = open_dict(timer->index, 1); // really open
    if(fp == NULL) return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    while(1) {
        int ch;
        pthread_cleanup_push((void*)&close_dict, (void*)(uintptr_t)timer->index);
        while(has_next(fp, ch)) {
            if(!ch) continue; // skip null bytes
            SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
            if(!spb) continue; // skip error bytes
            dict_t* d = (dict_t*)spb->target;
            if(!strcmp(timer->dat, d->key)) {
                ret = send_data(timer->accept_fd, timer->index, ACKSUCC, d->data, last_nonnull(d->data, DICTDATSZ));
                break;
            }
        }
        pthread_cleanup_pop(1);
        break;
    }

    if(!~ret) return send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4);
    return ret;
}

static int s2_set(thread_timer_t *timer) {
    memset(&setdicts[timer->index], 0, sizeof(dict_t));
    strncpy(setdicts[timer->index].key, timer->dat, DICTKEYSZ-1);
    md5((uint8_t*)timer->dat, strlen(timer->dat)+1, (uint8_t*)setdicts[timer->index].data);
    return send_data(timer->accept_fd, timer->index, ACKDATA, "data", 4);
}

static int insert_item(FILE *fp, const dict_t* dict, int keysize, int datasize) {
    int ch;
    const char* key = dict->key;
    const char* data = dict->data;
    uint8_t buf[8+DICTSZ];
    while(has_next(fp, ch)) {
        if(!ch) continue; // skip null bytes
        SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
        if(!spb) {
            fputs("Bad spb file", stderr);
            pthread_exit(NULL);
        }
        dict_t* d = (dict_t*)spb->target;
        if(memcmp(key, d->key, keysize)) continue;
        int datalen = last_nonnull(d->data, DICTDATSZ);
        if(datalen == datasize) { // 新增 data 可以直接覆盖到原 data
            if(fseek(fp, -(int)(spb->real_len), SEEK_CUR)) goto ERR_INSERT_ITEM;
            goto TRY_INSERT_ITEM;
        }
        uint32_t next = ftell(fp);
        uint32_t this = next - spb->real_len;
        if(fseek(fp, 0, SEEK_END)) goto ERR_INSERT_ITEM;
        uint32_t end = ftell(fp);
        if(next == end) {
            if(!ftruncate(fileno(fp), end - spb->real_len)) {
                if(fseek(fp, 0, SEEK_END)) goto ERR_INSERT_ITEM;
                goto TRY_INSERT_ITEM;
            }
            goto ERR_INSERT_ITEM;
        }
        uint32_t cap = end - next;
        #ifdef DEBUG
            printf("this: %u, next: %u, end: %u, cap: %u\n", this, next, end, cap);
        #endif
        char* data = malloc(cap);
        int iserr = 1;
        if(data) {
            pthread_cleanup_push((void*)&free, data);
            while(1) {
                if(fseek(fp, next, SEEK_SET)) {
                    iserr = 1;
                    break;
                }
                if(fread(data, cap, 1, fp) == 1) {
                    if(!ftruncate(fileno(fp), end - spb->real_len)) {
                        if(fseek(fp, this, SEEK_SET)) {
                            iserr = 1;
                            break;
                        }
                        if(fwrite(data, cap, 1, fp) == 1) {
                            iserr = 0;
                            break;
                        }
                    }
                }
                break;
            }
            pthread_cleanup_pop(1);
        }
        if(iserr) goto ERR_INSERT_ITEM;
        break;
    }
    if(fseek(fp, 0, SEEK_END)) goto ERR_INSERT_ITEM;
TRY_INSERT_ITEM:
    if(set_pb(fp, items_len, sizeof(dict_t), dict))
        return 0;
ERR_INSERT_ITEM:
    return 1;
}

static int s3_set_data(thread_timer_t *timer) {
    if(!setdicts[timer->index].data[0]) return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    FILE *fp = open_dict(timer->index, 0);
    if(fp == NULL) return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);

    int datasize = (timer->numbytes > (DICTDATSZ-1))?(DICTDATSZ-1):timer->numbytes;
    #ifdef DEBUG
        printf("Set data size: %u\n", datasize);
    #endif
    if(datasize <= 0 || datasize > sizeof(setdicts[timer->index].data)) 
        return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);

    int r;
    pthread_cleanup_push((void*)&close_dict, (void*)(uintptr_t)timer->index);

    uint8_t* dp = (uint8_t*)setdicts[timer->index].data;
    touch_timer(timer);
    int p = ((*((uint32_t*)dp))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
    dict_t* setdict;

    if(!dict_pool[p]) {
        setdict = dict_pool[p] = (dict_t*)malloc(sizeof(dict_t));
        memcpy(setdict->key, setdicts[timer->index].key, DICTKEYSZ);
    }
    else {
        int c = 16-4;
        int notok;
        while(dict_pool[p] && (notok=strcmp(setdicts[timer->index].key, dict_pool[p]->key)) && c-->0) {
            #ifdef DEBUG
                printf("digest of %s: %08x got conflicted, remaining chance: %d.\n", setdicts[timer->index].key, p, c);
            #endif
            p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
            #ifdef DEBUG
                printf("skip digest of %s to %08x.\n", setdicts[timer->index].key, p);
            #endif
        }
        if(!dict_pool[p]) {
            setdict = dict_pool[p] = (dict_t*)malloc(sizeof(dict_t)); // 无值
            memcpy(setdict->key, setdicts[timer->index].key, DICTKEYSZ);
        }
        else if(notok) setdict = &setdicts[timer->index]; // 全部冲突
        else setdict = dict_pool[p]; // 已有值
    }
    #ifdef DEBUG
        printf("item %s(%0*x) will fill into %p.\n", setdicts[timer->index].key, DICTPOOLBIT/4, p, dict_pool[p]);
    #endif

    memset(setdict->data, 0, DICTDATSZ);
    memcpy(setdict->data, timer->dat, timer->numbytes);

    if(insert_item(fp, setdict, strlen(setdict->key)+1, datasize)) {
        fprintf(stderr, "Error set data: dict[%s]=%s\n", setdict->key, timer->dat);
        r = send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    } else {
        printf("Set dict[%s]=%s\n", setdict->key, timer->dat);
        r = send_data(timer->accept_fd, timer->index,  ACKSUCC, "succ", 4);
    }

    setdicts[timer->index].data[0] = 0;

    pthread_cleanup_pop(1);
    return r;
}

static server_ack_t del(FILE *fp, const char* key, int len, char ret[4]) {
    int ch;
    uint8_t buf[8+DICTSZ];
    while(has_next(fp, ch)) {
        if(!ch) continue; // skip null bytes
        SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
        if(!spb)  {
            fputs("Bad spb file", stderr);
            pthread_exit(NULL);
        }
        dict_t* d = (dict_t*)spb->target;
        if(memcmp(key, d->key, len)) continue;
        uint32_t next = ftell(fp);
        uint32_t this = next - spb->real_len;
        if(fseek(fp, 0, SEEK_END)) {
            *(uint32_t*)ret = *(uint32_t*)"erro";
            return ACKERRO;
        }
        uint32_t end = ftell(fp);
        if(next == end) {
            if(!ftruncate(fileno(fp), end - spb->real_len)) {
                *(uint32_t*)ret = *(uint32_t*)"succ";
                return ACKSUCC;
            }
            *(uint32_t*)ret = *(uint32_t*)"erro";
            return ACKERRO;
        }
        uint32_t cap = end - next;
        #ifdef DEBUG
            printf("this: %u, next: %u, end: %u, cap: %u\n", this, next, end, cap);
        #endif
        char* data = malloc(cap);
        server_ack_t ack = 0;
        if(data) {
            pthread_cleanup_push((void*)&free, data);
            while(1) {
                if(fseek(fp, next, SEEK_SET)) {
                    *(uint32_t*)ret = *(uint32_t*)"erro";
                    ack = ACKERRO;
                    break;
                }
                if(fread(data, cap, 1, fp) == 1) {
                    if(!ftruncate(fileno(fp), end - spb->real_len)) {
                        if(fseek(fp, this, SEEK_SET))  {
                            *(uint32_t*)ret = *(uint32_t*)"erro";
                            ack = ACKERRO;
                            break;
                        }
                        if(fwrite(data, cap, 1, fp) == 1) {
                            *(uint32_t*)ret = *(uint32_t*)"succ";
                            ack = ACKSUCC;
                            break;
                        }
                    }
                }
                break;
            }
            pthread_cleanup_pop(1);
        }
        if(ack) return ack;
        *(uint32_t*)ret = *(uint32_t*)"erro";
        return ACKERRO;
    }
    *(uint32_t*)ret = *(uint32_t*)"null";
    return ACKNULL;
}

static int s4_del(thread_timer_t *timer) {
    uint8_t digest[16];
    char ret[4];
    int r;
    FILE *fp = open_dict(timer->index, 0);
    if(fp == NULL) return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);

    pthread_cleanup_push((void*)&close_dict, (void*)(uintptr_t)timer->index);
    while(1) {
        md5((uint8_t*)timer->dat, strlen(timer->dat)+1, digest);
        uint8_t* dp = digest;
        int p = ((*((uint32_t*)digest))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ;
        int c = 16-4;
        int notok = 1;
        while(dict_pool[p] && (notok=strcmp(timer->dat, dict_pool[p]->key)) && c-->0) {
            #ifdef DEBUG
                printf("digest of %s: %08x got conflicted, remaining chance: %d.\n", timer->dat, p, c);
            #endif
            p = ((*((uint32_t*)(++dp)))>>(8*sizeof(uint32_t)-DICTPOOLBIT))&DICTPOOLSZ; // 哈希碰撞
            #ifdef DEBUG
                printf("skip digest of %s to %08x.\n", timer->dat, p);
            #endif
        }
        if(!dict_pool[p] || notok) {
            r = send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4);
            break;
        }
        free(dict_pool[p]);
        dict_pool[p] = NULL;
        r = send_data(timer->accept_fd, timer->index, del(fp, timer->dat, timer->numbytes+1, ret), ret, 4);
        break;
    }
    pthread_cleanup_pop(1);
    return r;
}

static int s5_md5(thread_timer_t *timer) {
    FILE* fp = open_dict(timer->index, 1);
    if(fp == NULL) return send_data(timer->accept_fd, timer->index, ACKERRO, "erro", 4);
    int r;
    pthread_cleanup_push((void*)&close_dict, (void*)(uintptr_t)timer->index);
    fill_md5(fp);
    r = is_dict_md5_equal((uint8_t*)timer->dat);
    pthread_cleanup_pop(1);
    if(r) return send_data(timer->accept_fd, timer->index, ACKNULL, "null", 4);
    else return send_data(timer->accept_fd, timer->index, ACKNEQU, "nequ", 4);
}

static void handle_quit(int signo) {
    puts("Handle sigquit");
    fflush(stdout);
    pthread_exit(NULL);
}

static void handle_segv(int signo) {
    puts("Handle sigsegv");
    fflush(stdout);
    pthread_exit(NULL);
}

static void handle_kill(int signo) {
    puts("Handle sigkill/sigterm");
    process_defer();
}

static void accept_timer(void *p) {
    thread_timer_t *timer = timer_pointer_of(p);
    uint32_t index = timer->index;
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE); // 防止处理嵌套
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    sleep(MAXWAITSEC / 4);
    while(timer->thread && !pthread_kill(timer->thread, 0)) {
        pthread_rwlock_rdlock(&timer->mb);
        uint8_t isbusy = timer->isbusy;
        pthread_rwlock_unlock(&timer->mb);
        if(!isbusy) {
            pthread_mutex_lock(&timer->tmc);
            timer->hastimerslept = 1;
            puts("Timer sleep");
            pthread_cond_wait(&timer->tc, &timer->tmc);
            timer->hastimerslept = 0;
            pthread_mutex_unlock(&timer->tmc);
            puts("Timer wake up");
            sleep(MAXWAITSEC / 4);
        }
        if(is_dict_opening) touch_timer(p);
        time_t waitsec = time(NULL) - timer->touch;
        printf("Wait sec: %u, max: %u\n", (unsigned int)waitsec, MAXWAITSEC);
        if(waitsec > MAXWAITSEC) {
            pthread_t thread = timer->thread;
            if(thread) {
                pthread_kill(thread, SIGQUIT);
                puts("Kill thread");
            }
            break;
        }
        sleep(MAXWAITSEC / 4);
    }
    pthread_mutex_lock(&timer->tmc);
    timer->timerthread = NULL;
    timer->hastimerslept = 0;
    pthread_mutex_unlock(&timer->tmc);
}

static void cleanup_thread(thread_timer_t* timer) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE); // 防止处理嵌套
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
    printf("Start cleaning, ");
    if(timer->accept_fd) {
        close(timer->accept_fd);
        timer->accept_fd = 0;
        printf("Close accept, ");
    }
    close_dict(timer->index);
    timer->thread = 0;
    pthread_cond_destroy(&timer->c);
    printf("Destroy accept cond, ");
    pthread_mutex_destroy(&timer->mc);
    printf("Destroy accept mutex, ");
    setdicts[timer->index].data[0] = 0;
    pthread_rwlock_wrlock(&timer->mb);
    timer->isbusy = 0;
    printf("Clear busy, ");
    pthread_rwlock_unlock(&timer->mb);
    puts("Finish cleaning");
}

static void process_defer() {
    for(int i = 0; i < THREADCNT; i++) {
        if(timers[i].thread) pthread_kill(timers[i].thread, SIGQUIT);
        pthread_cond_destroy(&timers[i].tc);
        pthread_mutex_destroy(&timers[i].tmc);
        if(timers[i].timerthread) pthread_kill(timers[i].timerthread, SIGQUIT);
    }
    fflush(stdout);
    pthread_exit(NULL);
}

static void handle_int(int signo) {
    puts("Keyboard interrupted");
    process_defer();
}

static void handle_pipe(int signo) {
    puts("Pipe error, exit thread...");
    fflush(stdout);
    pthread_exit(NULL);
}

static void handle_accept(void *p) {
    #ifdef DEBUG
        printf("accept ptr: %p\n", p);
    #endif
    pthread_cleanup_push((void*)&cleanup_thread, p);
    puts("Handling accept...");
    while(1) {
        int accept_fd = timer_pointer_of(p)->accept_fd;
        uint32_t index = timer_pointer_of(p)->index;
        uint8_t *buff = timer_pointer_of(p)->buf;
        cmdpacket_t cp = (cmdpacket_t)buff;
        ssize_t numbytes = 0, offset = 0;
        while(
                offset >= CMDPACKET_HEAD_LEN
                || (numbytes = recv(accept_fd, buff+offset, CMDPACKET_HEAD_LEN-offset, MSG_WAITALL)) > 0
            ) {
            touch_timer(p);
            offset += numbytes;
            #ifdef DEBUG
                printf("[handle] Get %zd bytes, total: %zd.\n", numbytes, offset);
            #endif
            if(offset < CMDPACKET_HEAD_LEN) break;
            if(offset < CMDPACKET_HEAD_LEN+(ssize_t)(cp->datalen)) {
                ssize_t toread = CMDPACKET_HEAD_LEN+(ssize_t)(cp->datalen)-offset;
                numbytes = recv(accept_fd, buff+offset, toread, MSG_WAITALL);
                if(numbytes != toread) break;
                else {
                    offset += numbytes;
                    #ifdef DEBUG
                        printf("[handle] Get %zd bytes, total: %zd.\n", numbytes, offset);
                    #endif
                }
            }
            numbytes = CMDPACKET_HEAD_LEN+(ssize_t)(cp->datalen); // 暂存 packet len
            if(offset < numbytes) break;
            #ifdef DEBUG
                printf("[handle] Decrypt %d bytes data...\n", (int)cp->datalen);
            #endif
            if(cp->cmd <= CMDEND) {
                if(!cmdpacket_decrypt(cp, index, cfg.pwd)) {
                    cp->data[cp->datalen] = 0;
                    timer_pointer_of(p)->dat = (char*)cp->data;
                    timer_pointer_of(p)->numbytes = (ssize_t)(cp->datalen);
                    printf("[normal] Get %zd bytes packet with cmd: %d, data: %s\n", offset, cp->cmd, cp->data);
                    switch(cp->cmd) {
                        case CMDGET:
                            if(!has_dict_opened && !s1_get(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDCAT:
                            if(!has_dict_opened && !send_all(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDMD5:
                            if(!has_dict_opened && !s5_md5(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDACK:
                        case CMDEND:
                        default: goto CONV_END; break;
                    }
                } else {
                    puts("Decrypt normal data failed");
                    break;
                }
            } else if(cp->cmd <= CMDDAT) {
                if(!cmdpacket_decrypt(cp, index, cfg.sps)) {
                    cp->data[cp->datalen] = 0;
                    timer_pointer_of(p)->dat = (char*)cp->data;
                    timer_pointer_of(p)->numbytes = (ssize_t)(cp->datalen);
                    printf("[super] Get %zd bytes packet with data: %s\n", offset, cp->data);
                    switch(cp->cmd) {
                        case CMDSET:
                            if(!has_dict_opened && !s2_set(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDDEL:
                            if(!has_dict_opened && !s4_del(timer_pointer_of(p))) goto CONV_END;
                        break;
                        case CMDDAT:
                            if(!has_dict_opened && !s3_set_data(timer_pointer_of(p))) goto CONV_END;
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
        if(timer_pointer_of(p)->accept_fd) {
            close(timer_pointer_of(p)->accept_fd);
            timer_pointer_of(p)->accept_fd = 0;
            puts("Close accept");
        }
        close_dict(timer_pointer_of(p)->index);
        setdicts[timer_pointer_of(p)->index].data[0] = 0;
        pthread_rwlock_wrlock(&timer_pointer_of(p)->mb);
        timer_pointer_of(p)->isbusy = 0;
        pthread_mutex_lock(&timer_pointer_of(p)->mc);
        pthread_rwlock_unlock(&timer_pointer_of(p)->mb);
        puts("Set thread status to idle");
        pthread_cond_wait(&timer_pointer_of(p)->c, &timer_pointer_of(p)->mc);
        pthread_mutex_unlock(&timer_pointer_of(p)->mc);
        puts("Thread wakeup");
    }
    pthread_cleanup_pop(1);
}

static void accept_client(int fd) {
    /*pid_t pid = fork();
    while (pid > 0) {      // 主进程监控子进程状态，如果子进程异常终止则重启之
        wait(NULL);
        puts("Server subprocess exited. Restart...");
        pid = fork();
    }
    while(pid < 0) {
        perror("Error when forking a subprocess");
        sleep(1);
    }*/
    signal(SIGINT,  handle_int);
    signal(SIGQUIT, handle_quit);
    signal(SIGKILL, handle_kill);
    signal(SIGSEGV, handle_segv);
    signal(SIGPIPE, handle_pipe);
    signal(SIGTERM, handle_kill);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    init_crypto();
    init_dict_pool(open_dict(0, 1));
    close_dict(0);
    for(int i = 0; i < THREADCNT; i++) pthread_rwlock_init(&timers[i].mb, NULL);
    while(1) {
        int p = 0;
        while(p < THREADCNT) {
            pthread_rwlock_rdlock(&timers[p].mb);
            if(!timers[p].isbusy) break;
            pthread_rwlock_unlock(&timers[p].mb);
            p++;
        }
        if(p >= THREADCNT) {
            puts("Max thread cnt exceeded");
            sleep(1);
            continue;
        }
        printf("Ready for accept on slot No.%d, ", p);
        thread_timer_t* timer = &timers[p];
        pthread_rwlock_unlock(&timer->mb);
        pthread_rwlock_wrlock(&timer->mb);
        timer->isbusy = 1;
        pthread_rwlock_unlock(&timer->mb);
        puts("Set thread status to busy, waitting...");
        #ifdef LISTEN_ON_IPV6
            struct sockaddr_in6 client_addr;
        #else
            struct sockaddr_in client_addr;
        #endif
        int accept_fd;
        while((accept_fd=accept(fd, (struct sockaddr *)&client_addr, &struct_len))<=0) {
            perror("Accept client error");
            pthread_rwlock_wrlock(&timer->mb);
            timer->isbusy = 0;
            pthread_rwlock_unlock(&timer->mb);
            continue;
        }
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
        time_t t = time(NULL);
        printf("\n> %sAccept client %s:%u at slot No.%d, ", ctime(&t), str, port, p);
        timer->accept_fd = accept_fd;
        timer->index = p;
        timer->touch = time(NULL);
        reset_seq(p);
        // start or wakeup accept thread
        if(timer->thread) {
            pthread_mutex_lock(&timer->mc);
            pthread_cond_signal(&timer->c); // wakeup thread
            pthread_mutex_unlock(&timer->mc);
            puts("Pick thread from pool");
        } else {
            pthread_cond_init(&timer->c, NULL);
            pthread_mutex_init(&timer->mc, NULL);
            if (pthread_create(&timer->thread, &attr, (void *)&handle_accept, timer)) {
                perror("Error creating thread");
                cleanup_thread(timer);
                putchar('\n');
                continue;
            }
            puts("Thread created");
        }
        // start or wakeup timer thread
        pthread_t thread = timer->timerthread;
        uint8_t hastimerslept = timer->hastimerslept;
        if(!thread || pthread_kill(thread, 0)) {
            printf("Creating timer thread...");
            pthread_cond_init(&timer->tc, NULL);
            pthread_mutex_init(&timer->tmc, NULL);
            if (pthread_create(&timer->timerthread, &attr, (void *)&accept_timer, timer)) {
                perror("Error creating timer thread");
                cleanup_thread(timer);
                putchar('\n');
                continue;
            }
            puts("succeeded");
            pthread_mutex_lock(&timer->tmc);
            timer->hastimerslept = 0;
            pthread_mutex_unlock(&timer->tmc);
        } else if(hastimerslept) {
            printf("Waking up timer thread...");
            pthread_mutex_lock(&timer->tmc);
            pthread_cond_signal(&timer->tc); // wakeup thread
            pthread_mutex_unlock(&timer->tmc);
            puts("succeeded");
        }
    }
}

#define argequ(i, arg) (*(uint16_t*)argv[i] == *(uint16_t*)(arg))
#define showUsage(program) \
    printf("Usage:\n%s [-d] listen_port dict_file [ config_file | - ]\n\t-d: As daemon\n\t- : Read config from env SDS_PWD & SDS_SPS\n", program)
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
        perror("Start daemon error");
        return 2;
    }
    FILE *fp = NULL;
    fp = fopen(argv[as_daemon?3:2], "rb+");
    if(!fp) fp = fopen(argv[as_daemon?3:2], "wb+");
    if(!fp) {
        fprintf(stderr, "Error opening dict file: %s", argv[as_daemon?3:2]);
        perror("");
        return 3;
    }
    fclose(fp);
    if(init_dict(argv[as_daemon?3:2]))
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
        fprintf(stderr, "Error opening config file: %s", argv[as_daemon?4:3]);
        perror("fopen");
        return 7;
    }
    if(~((int)fp)) {
        uint8_t buf[8+sizeof(config_t)];
        SIMPLE_PB* spb = read_pb_into(fp, (SIMPLE_PB*)buf);
        if(!spb) {
            fprintf(stderr, "Error reading config file: %s\n", argv[as_daemon?4:3]);
            return 8;
        }
        cfg = *(config_t*)(spb->target);
        fclose(fp);
    }
    items_len = align_struct(sizeof(dict_t), 2, setdicts[0].key, setdicts[0].data);
    if(!items_len) {
        fputs("Align struct error", stderr);
        return 9;
    }
    int fd;
    if(!(fd=bind_server((uint16_t*)&port))) return 10;
    if(!listen_socket(fd)) return 11;
    pthread_cleanup_push((void*)&close, (void*)((long long)fd));
    accept_client(fd);
    pthread_cleanup_pop(1);
    return 0;
}
