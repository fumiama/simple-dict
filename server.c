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
    static struct sockaddr_in6 client_addr;
#else
    static socklen_t struct_len = sizeof(struct sockaddr_in);
    static struct sockaddr_in server_addr;
    static struct sockaddr_in client_addr;
#endif

struct THREADTIMER {
    uint32_t index;
    time_t touch;
    int accept_fd;
    ssize_t numbytes;
    char *dat, *ptr;
    char lock_type;
};
typedef struct THREADTIMER THREADTIMER;

static int fd;      // server fd
static pthread_t accept_threads[THREADCNT];
static DICT d;
static uint32_t* items_len;
static CONFIG* cfg;
static pthread_attr_t attr;

#define showUsage(program) printf("Usage: %s [-d] listen_port try_times dict_file config_file\n\t-d: As daemon\n", program)

static void accept_client();
static void accept_timer(void *p);
static int bind_server(uint16_t port, int try_times);
static int close_and_send(THREADTIMER* timer, char *data, size_t numbytes);
static void handle_accept(void *accept_fd_p);
static void handle_pipe(int signo);
static void handle_quit(int signo);
static void kill_thread(THREADTIMER* timer);
static uint32_t last_nonnull(char* p, uint32_t max_size);
static int listen_socket(int try_times);
static int send_all(THREADTIMER *timer);
static int send_data(int accept_fd, int index, char *data, size_t length);
static int s1_get(THREADTIMER *timer);
static int s2_set(THREADTIMER *timer);
static int s3_set_data(THREADTIMER *timer);
static int s4_del(THREADTIMER *timer);
static int s5_md5(THREADTIMER *timer);

static int bind_server(uint16_t port, int try_times) {
    int fail_count = 0;
    int result = -1;
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
    while(!~(result = bind(fd, (struct sockaddr *)&server_addr, struct_len)) && fail_count++ < try_times) sleep(1);
    if(!~result && fail_count >= try_times) {
        puts("Bind server failure!");
        return 0;
    } else{
        puts("Bind server success!");
        return 1;
    }
}

static int listen_socket(int try_times) {
    int fail_count = 0;
    int result = -1;
    while(!~(result = listen(fd, 10)) && fail_count++ < try_times) sleep(1);
    if(!~result && fail_count >= try_times) {
        puts("Listen failed!");
        return 0;
    } else{
        puts("Listening....");
        return 1;
    }
}

static uint32_t last_nonnull(char* p, uint32_t max_size) {
    if(max_size > 1) while(!p[max_size - 1]) max_size--;
    return max_size;
}

static int send_data(int accept_fd, int index, char *data, size_t length) {
    char buf[CMDPACKET_LEN_MAX];
    CMDPACKET* p = (CMDPACKET*)buf;
    p->cmd = CMDACK;
    p->datalen = length;
    memcpy(p->data, data, p->datalen);
    cmdpacket_encrypt(p, index, cfg->pwd);
    if(!~send(accept_fd, buf, CMDPACKET_HEAD_LEN+p->datalen, 0)) {
        puts("Send data error");
        return 0;
    } else {
        printf("Send data: ");
        puts(data);
        return 1;
    }
}

static int send_all(THREADTIMER *timer) {
    int re = 1;
    FILE *fp = open_dict(DICT_LOCK_SH, timer->index);
    if(fp) {
        timer->lock_type = DICT_LOCK_SH;
        off_t len = 0, file_size = get_dict_size();
        char* buf = (char*)malloc(file_size);
        if(buf) {
            if(fread(buf, file_size, 1, fp) == 1) {
                #ifdef DEBUG
                    printf("Get dict file size: %zu\n", file_size);
                #endif
                char* encbuf = raw_encrypt(buf, &file_size, timer->index, cfg->pwd);
                sprintf(timer->dat, "%zu$", file_size);
                //printf("Get encrypted file size: %s\n", timer->dat);
                //FILE* fp = fopen("raw_after_enc", "wb+");
                //fwrite(encbuf, file_size, 1, fp);
                //fclose(fp);
                if(send(timer->accept_fd, timer->dat, strlen(timer->dat), 0) > 0) {
                    re = send(timer->accept_fd, encbuf, file_size, 0);
                    printf("Send %u bytes.\n", re);
                    close_dict(DICT_LOCK_SH, timer->index);
                } else re = 0;
                free(encbuf);
            }
            free(buf);
        }
    }
    return re;
}

#define has_next(fp, ch) ((ch=getc(fp)),(feof(fp)?0:(ungetc(ch,fp),1)))

static int s1_get(THREADTIMER *timer) {
    FILE *fp = open_dict(DICT_LOCK_SH, timer->index);
    //timer->status = 0;
    if(fp) {
        int ch;
        timer->lock_type = DICT_LOCK_SH;
        while(has_next(fp, ch)) {
            SIMPLE_PB* spb = get_pb(fp);
            DICT* d = (DICT*)spb->target;
            if(!strcmp(timer->dat, d->key)) {
                int r = close_and_send(timer, d->data, last_nonnull(d->data, DICTDATSZ));
                free(spb);
                return r;
            } else free(spb);
        }
    }
    return close_and_send(timer, "null", 4);
}

static int s2_set(THREADTIMER *timer) {
    FILE *fp = open_dict(DICT_LOCK_EX, timer->index);
    if(fp) {
        timer->lock_type = DICT_LOCK_EX;
        //timer->status = 3;
        memset(&d, 0, sizeof(DICT));
        strncpy(d.key, timer->dat, DICTKEYSZ-1);
        fseek(fp, 0, SEEK_END);
        return send_data(timer->accept_fd, timer->index, "data", 4);
    } else {
        timer->lock_type = DICT_LOCK_UN;
        //timer->status = 0;
        return send_data(timer->accept_fd, timer->index, "erro", 4);
    }
}

static int s3_set_data(THREADTIMER *timer) {
    //timer->status = 0;
    uint32_t datasize = (timer->numbytes > (DICTDATSZ-1))?(DICTDATSZ-1):timer->numbytes;
    #ifdef DEBUG
        printf("Set data size: %u\n", datasize);
    #endif
    memcpy(d.data, timer->dat, datasize);
    if(!set_pb(get_dict_fp(timer->index), items_len, sizeof(DICT), &d)) {
        printf("Error set data: dict[%s]=%s\n", d.key, timer->dat);
        return close_and_send(timer, "erro", 4);
    } else {
        printf("Set data: dict[%s]=%s\n", d.key, timer->dat);
        return close_and_send(timer, "succ", 4);
    }
}

static int s4_del(THREADTIMER *timer) {
    FILE *fp = open_dict(DICT_LOCK_EX, timer->index);
    //timer->status = 0;
    if(fp) {
        int ch;
        timer->lock_type = DICT_LOCK_EX;
        while(has_next(fp, ch)) {
            SIMPLE_PB* spb = get_pb(fp);
            DICT* d = (DICT*)spb->target;
            if(!memcmp(timer->dat, d->key, timer->numbytes+1)) {
                uint32_t next = ftell(fp);
                uint32_t this = next - spb->real_len;
                fseek(fp, 0, SEEK_END);
                uint32_t end = ftell(fp);
                if(next == end) {
                    if(!ftruncate(fileno(fp), end - spb->real_len)) {
                        free(spb);
                        return close_and_send(timer, "succ", 4);
                    } else {
                        free(spb);
                        return close_and_send(timer, "erro", 4);
                    }
                } else {
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
                                    return close_and_send(timer, "succ", 4);
                                }
                            }
                        }
                        free(data);
                    }
                    free(spb);
                    return close_and_send(timer, "erro", 4);
                }
            } else free(spb);
        }
    }
    return close_and_send(timer, "null", 4);
}

static int s5_md5(THREADTIMER *timer) {
    //timer->status = 0;
    fill_md5();
    if(is_md5_equal((uint8_t*)timer->dat)) return send_data(timer->accept_fd, timer->index, "null", 4);
    else return send_data(timer->accept_fd, timer->index, "nequ", 4);
}

static void handle_quit(int signo) {
    printf("Handle quit with sig %d\n", signo);
    pthread_exit(NULL);
}

#define timer_pointer_of(x) ((THREADTIMER*)(x))
#define touch_timer(x) timer_pointer_of(x)->touch = time(NULL)

static void accept_timer(void *p) {
    THREADTIMER *timer = timer_pointer_of(p);
    uint32_t index = timer->index;
    while(accept_threads[index] && !pthread_kill(accept_threads[index], 0)) {
        sleep(MAXWAITSEC / 4);
        time_t waitsec = time(NULL) - timer->touch;
        printf("Wait sec: %u, max: %u\n", waitsec, MAXWAITSEC);
        if(waitsec > MAXWAITSEC) break;
    }
    puts("Call kill thread");
    kill_thread(timer);
    puts("Free timer");
    free(timer);
    puts("Finish calling kill thread\n");
}

static void kill_thread(THREADTIMER* timer) {
    puts("Start killing.");
    uint32_t index = timer->index;
    pthread_t thread = accept_threads[index];
    if(thread) {
        pthread_kill(thread, SIGQUIT);
        accept_threads[index] = 0;
        puts("Kill thread.");
    }
    if(timer->accept_fd) {
        close(timer->accept_fd);
        timer->accept_fd = 0;
        puts("Close accept.");
    }
    if(timer->ptr) {
        free(timer->ptr);
        timer->ptr = NULL;
        puts("Free data.");
    }
    if(timer->lock_type) close_dict(timer->lock_type, timer->index);
    puts("Finish killing.");
}

static void handle_pipe(int signo) {
    printf("Pipe error: %d\n", signo);
    pthread_exit(NULL);
}

static void handle_accept(void *p) {
    int accept_fd = timer_pointer_of(p)->accept_fd;
    if(accept_fd > 0) {
        puts("\nConnected to the client.");
        pthread_t thread;
        if (pthread_create(&thread, &attr, (void *)&accept_timer, p)) puts("Error creating timer thread");
        else puts("Creating timer thread succeeded");
        //send_data(accept_fd, "Welcome to simple dict server.", 31);
        //timer_pointer_of(p)->status = -1;
        uint32_t index = timer_pointer_of(p)->index;
        char *buff = calloc(BUFSIZ, sizeof(char));
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
                    printf("[handle] Decrypt %zd bytes data...\n", cp->datalen);
                #endif
                if(cp->cmd < 5) {
                    if(cmdpacket_decrypt(cp, index, cfg->pwd)) {
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
                        puts("Decrypt normal data failed.");
                        break;
                    }
                } else if(cp->cmd < 8) {
                    if(cmdpacket_decrypt(cp, index, cfg->sps)) {
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
                        puts("Decrypt super data failed.");
                        break;
                    }
                } else {
                    puts("Invalid command.");
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
            CONV_END: puts("Conversation end\n");
        } else puts("Error allocating buffer");
        accept_threads[index] = 0;
        kill_thread(timer_pointer_of(p));
    } else puts("Error accepting client");
}

pid_t pid;
static void accept_client() {
    pid = fork();
    while (pid > 0) {      //主进程监控子进程状态，如果子进程异常终止则重启之
        wait(NULL);
        puts("Server subprocess exited. Restart...");
        pid = fork();
    }
    signal(SIGQUIT, handle_quit);
    signal(SIGPIPE, handle_pipe);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
    init_crypto();
    if(pid < 0) puts("Error when forking a subprocess.");
    else while(1) {
        puts("Ready for accept, waitting...");
        int p = 0;
        while(p < THREADCNT && accept_threads[p] && !pthread_kill(accept_threads[p], 0)) p++;
        if(p < THREADCNT) {
            printf("Next thread is No.%d\n", p);
            THREADTIMER *timer = malloc(sizeof(THREADTIMER));
            if(timer) {
                timer->accept_fd = accept(fd, (struct sockaddr *)&client_addr, &struct_len);
                if(timer->accept_fd <= 0) {
                    free(timer);
                    puts("Accept client error.");
                } else {
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
                    timer->index = p;
                    timer->touch = time(NULL);
                    timer->ptr = NULL;
                    reset_seq(p);
                    if (pthread_create(accept_threads + p, &attr, (void *)&handle_accept, timer)) puts("Error creating thread");
                    else puts("Creating thread succeeded");
                }
            } else puts("Allocate timer error");
        } else {
            puts("Max thread cnt exceeded");
            sleep(1);
        }
    }
}

static int close_and_send(THREADTIMER* timer, char *data, size_t numbytes) {
    close_dict(timer->lock_type, timer->index);
    return send_data(timer->accept_fd, timer->index, data, numbytes);
}

#define argequ(i, arg) (*(uint16_t*)argv[i] == *(uint16_t*)(arg))
int main(int argc, char *argv[]) {
    if(argc != 5 && argc != 6) showUsage(argv[0]);
    else {
        int port = 0;
        int as_daemon = argequ(1, "-d");
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
                        fclose(fp);
                        init_dict(argv[as_daemon?4:3]);
                        fp = NULL;
                        fp = fopen(argv[as_daemon?5:4], "rb");
                        if(fp) {
                            SIMPLE_PB* spb = get_pb(fp);
                            cfg = (CONFIG*)spb->target;
                            fclose(fp);
                            items_len = align_struct(sizeof(DICT), 2, d.key, d.data);
                            if(items_len) {
                                if(bind_server(port, times)) if(listen_socket(times)) accept_client();
                            } else puts("Align struct error.");
                        } else printf("Error opening config file: %s\n", argv[as_daemon?5:4]);
                    } else printf("Error opening dict file: %s\n", argv[as_daemon?4:3]);
                } else puts("Start daemon error");
            } else printf("Error times: %d\n", times);
        } else printf("Error port: %d\n", port);
    }
    close(fd);
    exit(EXIT_FAILURE);
}
