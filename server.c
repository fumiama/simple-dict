#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#if !__APPLE__
    #include <sys/sendfile.h> 
#endif

#define PASSWORD "fumiama"
#define SETPASS "minamoto"

int fd;
//ssize_t numbytes;
socklen_t struct_len = sizeof(struct sockaddr_in);
struct sockaddr_in server_addr;
//char buff[BUFSIZ];
char *file_path;

#define THREADCNT 16
pthread_t accept_threads[THREADCNT];

#define MAXWAITSEC 10
struct THREADTIMER {
    pthread_t *thread;
    time_t touch;
    int accept_fd;
    ssize_t numbytes;
    char *data;
    char status;
    char is_open;
    FILE *fp;
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

void accept_client();
void accept_timer(void *p);
int bind_server(uint16_t port, u_int try_times);
int check_buffer(THREADTIMER *timer);
void close_dict(FILE *fp);
int close_and_send(THREADTIMER *timer, char *data, size_t numbytes);
off_t file_size_of(const char* fname);
int free_after_send(int accept_fd, char *data, size_t length);
void handle_accept(void *accept_fd_p);
void handle_pipe(int signo);
void handle_quit(int signo);
void kill_thread(THREADTIMER* timer);
int listen_socket(u_int try_times);
FILE *open_dict(int lock_type);
int send_all(THREADTIMER *timer);
int send_data(int accept_fd, char *data, size_t length);
int sm1_pwd(THREADTIMER *timer);
int s0_init(THREADTIMER *timer);
int s1_get(THREADTIMER *timer);
int s2_set(THREADTIMER *timer);
int s3_set_data(THREADTIMER *timer);
int s4_del(THREADTIMER *timer);
int s5_list(THREADTIMER *timer);

int bind_server(uint16_t port, u_int try_times) {
    int fail_count = 0;
    int result = -1;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(server_addr.sin_zero), 8);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    while(!~(result = bind(fd, (struct sockaddr *)&server_addr, struct_len)) && fail_count++ < try_times) sleep(1);
    if(!~result && fail_count >= try_times) {
        puts("Bind server failure!");
        return 0;
    } else{
        puts("Bind server success!");
        return 1;
    }
}

int listen_socket(u_int try_times) {
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

int send_data(int accept_fd, char *data, size_t length) {
    if(!~send(accept_fd, data, length, 0)) {
        puts("Send data error");
        return 0;
    } else {
        printf("Send data: ");
        puts(data);
        return 1;
    }
}

int free_after_send(int accept_fd, char *data, size_t length) {
    int re = send_data(accept_fd, data, length);
    free(data);\
    return re;
}

int send_all(THREADTIMER *timer) {
    int re = 1;
    FILE *fp = open_dict(LOCK_SH);
    if(fp) {
        timer->fp = fp;
        timer->is_open = 1;
        off_t len = 0, file_size = file_size_of(file_path);
        sprintf(timer->data, "%zd", file_size);
        printf("Get file size: %s bytes.\n", timer->data);
        uint32_t head_len = strlen(timer->data);
        #if __APPLE__
            struct sf_hdtr hdtr;
            struct iovec headers;
            headers.iov_base = timer->data;
            headers.iov_len = head_len;
            hdtr.headers = &headers;
            hdtr.hdr_cnt = 1;
            hdtr.trailers = NULL;
            hdtr.trl_cnt = 0;
            re = !sendfile(fileno(fp), timer->accept_fd, 0, &len, &hdtr, 0);
        #else
            send_data(timer->accept_fd, timer->data, head_len);
            re = sendfile(timer->accept_fd, fileno(fp), &len, file_size) >= 0;
        #endif
        printf("Send %lld bytes.\n", len);
        close_dict(fp);
        timer->is_open = 0;
    }
    return re;
}

int sm1_pwd(THREADTIMER *timer) {
    if(!strcmp(PASSWORD, timer->data)) timer->status = 0;
    return !timer->status;
}

int s0_init(THREADTIMER *timer) {
    if(!strcmp("get", timer->data)) timer->status = 1;
    else if(!strcmp("set" SETPASS, timer->data)) timer->status = 2;
    else if(!strcmp("del" SETPASS, timer->data)) timer->status = 4;
    else if(!strcmp("lst", timer->data)) timer->status = 5;
    else if(!strcmp("cat", timer->data)) return send_all(timer);
    else if(!strcmp("quit", timer->data)) return 0;
    return send_data(timer->accept_fd, timer->data, timer->numbytes);
}

int s1_get(THREADTIMER *timer) {
    FILE *fp = open_dict(LOCK_SH);
    DICTBLK dict;
    timer->status = 0;
    if(fp) {
        timer->fp = fp;
        timer->is_open = 1;
        while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
            u_char ks = dict.keysize;
            dict.key[ks] = 0;
            //printf("[%s] Look key: (%d)%s\n", timer->data, ks, dict.key);
            if(!strcmp(timer->data, dict.key))
                return close_and_send(timer, dict.data, dict.datasize);
        }
    }
    return close_and_send(timer, "null", 4);
}

#define copyKey() {\
    dict.keysize = (timer->numbytes >= (DATASIZE-1))?(DATASIZE-1):timer->numbytes;\
    strncpy(dict.key, timer->data, (DATASIZE-1));\
}

int s2_set(THREADTIMER *timer) {
    FILE *fp = open_dict(LOCK_EX);
    if(fp) {
        timer->status = 3;
        timer->fp = fp;
        timer->is_open = 1;
        while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
            u_char ks = dict.keysize;
            dict.key[ks] = 0;
            //printf("[%zd] Key size: %d\n", timer->numbytes, ks);
            if(!dict.keysize || !strcmp(timer->data, dict.key)) {
                copyKey();
                fseek(fp, -DICTBLKSZ, SEEK_CUR);
                return send_data(timer->accept_fd, "data", 4);
            }
        }
        copyKey();
        fseek(fp, 0, SEEK_END);
        return send_data(timer->accept_fd, "data", 4);
    } else {
        timer->status = 0;
        return send_data(timer->accept_fd, "erro", 4);
    }
}

int s3_set_data(THREADTIMER *timer) {
    timer->status = 0;
    dict.datasize = (timer->numbytes >= (DATASIZE-1))?(DATASIZE-1):timer->numbytes;
    printf("Set data size: %d\n", dict.datasize);
    memcpy(dict.data, timer->data, dict.datasize);
    puts("Data copy to dict succ");
    if(fwrite(&dict, DICTBLKSZ, 1, timer->fp) != 1) {
        printf("Error set data: dict[%s]=%s\n", dict.key, timer->data);
        return close_and_send(timer, "erro", 4);
    } else {
        printf("Set data: dict[%s]=%s\n", dict.key, timer->data);
        return close_and_send(timer, "succ", 4);
    }
}

int s4_del(THREADTIMER *timer) {
    FILE *fp = open_dict(LOCK_EX);
    DICTBLK dict;
    timer->status = 0;
    if(fp) {
        timer->fp = fp;
        timer->is_open = 1;
        while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
            dict.key[dict.keysize] = 0;
            if(!strcmp(timer->data, dict.key)) {
                fseek(fp, -DICTBLKSZ+(DATASIZE-1), SEEK_CUR);
                fputc(0, fp);
                return close_and_send(timer, "succ", 4);
            }
        }
    }
    return close_and_send(timer, "null", 4);
}

off_t file_size_of(const char* fname) {
    struct stat statbuf;
    if(stat(fname, &statbuf)==0) return statbuf.st_size;
    else return -1;
}

int s5_list(THREADTIMER *timer) {
    timer->status = 0;
    off_t size = file_size_of(file_path) / DICTBLKSZ;
    char *keys = calloc(size, DATASIZE);
    DICTBLK dict;
    FILE *fp = open_dict(LOCK_SH);
    if(keys && fp) {
        timer->fp = fp;
        timer->is_open = 1;
        keys[0] = 0;
        while(fread(&dict, DICTBLKSZ, 1, fp) > 0) {
            u_char ks = dict.keysize;
            dict.key[ks] = 0;
            //printf("[%s] Look key: (%d)%s\n", timer->data, ks, dict.key);
            if(strstr(dict.key, timer->data)) {
                strcat(keys, dict.key);
                strcat(keys, "\n");
            }
        }
        int len = strlen(keys);
        close_dict(fp);
        timer->is_open = 0;
        if(len > 0) return free_after_send(timer->accept_fd, keys, len);
        else return send_data(timer->accept_fd, "null", 4);
    } else {
        if(fp) close_dict(fp);
        timer->is_open = 0;
        return send_data(timer->accept_fd, "erro", 4);
    }
}

int check_buffer(THREADTIMER *timer) {
    printf("Status: %d\n", timer->status);
    switch(timer->status) {
        case -1: return sm1_pwd(timer); break;
        case 0: return s0_init(timer); break;
        case 1: return s1_get(timer); break;
        case 2: return s2_set(timer); break;
        case 3: return s3_set_data(timer); break;
        case 4: return s4_del(timer); break;
        case 5: return s5_list(timer); break;
        default: return -1; break;
    }
}

void handle_quit(int signo) {
    printf("Handle quit with sig %d\n", signo);
    pthread_exit(NULL);
}

#define timer_pointer_of(x) ((THREADTIMER*)(x))
#define touch_timer(x) timer_pointer_of(x)->touch = time(NULL)

void accept_timer(void *p) {
    pthread_detach(pthread_self());
    THREADTIMER *timer = timer_pointer_of(p);
    while(*(timer->thread) && !pthread_kill(*(timer->thread), 0)) {
        sleep(MAXWAITSEC / 4);
        puts("Check accept status");
        if(time(NULL) - timer->touch > MAXWAITSEC) break;
    }
    puts("Call kill thread");
    kill_thread(timer);
    puts("Free timer");
    free(timer);
    puts("Finish calling kill thread");
}

void kill_thread(THREADTIMER* timer) {
    puts("Start killing.");
    if(*(timer->thread)) {
        pthread_kill(*(timer->thread), SIGQUIT);
        *(timer->thread) = 0;
        puts("Kill thread.");
    }
    if(timer->accept_fd) {
        close(timer->accept_fd);
        timer->accept_fd = 0;
        puts("Close accept.");
    }
    if(timer->data) {
        free(timer->data);
        timer->data = NULL;
        puts("Free data.");
    }
    if(timer->is_open) {
        close_dict(timer->fp);
        timer->is_open = 0;
        puts("Close file.");
    }
    puts("Finish killing.");
}

void handle_pipe(int signo) {
    printf("Pipe error: %d\n", signo);
}

void handle_accept(void *p) {
    pthread_detach(pthread_self());
    int accept_fd = timer_pointer_of(p)->accept_fd;
    if(accept_fd > 0) {
        puts("Connected to the client.");
        signal(SIGQUIT, handle_quit);
        signal(SIGPIPE, handle_pipe);
        pthread_t thread;
        if (pthread_create(&thread, NULL, (void *)&accept_timer, p)) puts("Error creating timer thread");
        else puts("Creating timer thread succeeded");
        send_data(accept_fd, "Welcome to simple dict server.", 31);
        timer_pointer_of(p)->status = -1;
        char *buff = calloc(BUFSIZ, sizeof(char));
        if(buff) {
            timer_pointer_of(p)->data = buff;
            while(*(timer_pointer_of(p)->thread) && (timer_pointer_of(p)->numbytes = recv(accept_fd, buff, BUFSIZ, 0)) > 0) {
                touch_timer(p);
                buff[timer_pointer_of(p)->numbytes] = 0;
                printf("Get %zd bytes: %s\n", timer_pointer_of(p)->numbytes, buff);
                puts("Check buffer");
                if(!check_buffer(timer_pointer_of(p))) break;
            }
            printf("Break: recv %zd bytes\n", timer_pointer_of(p)->numbytes);
        } else puts("Error allocating buffer");
        *(timer_pointer_of(p)->thread) = 0;
        kill_thread(timer_pointer_of(p));
    } else puts("Error accepting client");
}

void accept_client() {
    pid_t pid = fork();
    while (pid > 0) {      //主进程监控子进程状态，如果子进程异常终止则重启之
        wait(NULL);
        puts("Server subprocess exited. Restart...");
        pid = fork();
    }
    if(pid < 0) puts("Error when forking a subprocess.");
    else while(1) {
        puts("Ready for accept, waitting...");
        int p = 0;
        while(p < THREADCNT && accept_threads[p] && !pthread_kill(accept_threads[p], 0)) p++;
        if(p < THREADCNT) {
            printf("Run on thread No.%d\n", p);
            THREADTIMER *timer = malloc(sizeof(THREADTIMER));
            if(timer) {
                struct sockaddr_in client_addr;
                timer->accept_fd = accept(fd, (struct sockaddr *)&client_addr, &struct_len);
                timer->thread = &accept_threads[p];
                timer->touch = time(NULL);
                timer->data = NULL;
                timer->is_open = 0;
                timer->fp = NULL;
                signal(SIGQUIT, handle_quit);
                signal(SIGPIPE, handle_pipe);
                if (pthread_create(timer->thread, NULL, (void *)&handle_accept, timer)) puts("Error creating thread");
                else puts("Creating thread succeeded");
            } else puts("Allocate timer error");
        } else {
            puts("Max thread cnt exceeded");
            sleep(1);
        }
    }
}

FILE *open_dict(int lock_type) {
    FILE *fp = NULL;
    fp = fopen(file_path, (lock_type == LOCK_SH)?"rb":"rb+");
    if(fp) {
        if(!~flock(fileno(fp), lock_type | LOCK_NB)) {
            printf("Error: ");
            fp = NULL;
        }
        printf("Open dict in mode %d\n", lock_type);
    } else puts("Open dict error");
    return fp;
}

int close_and_send(THREADTIMER *timer, char *data, size_t numbytes) {
    close_dict(timer->fp);
    timer->is_open = 0;
    return send_data(timer->accept_fd, data, numbytes);
}

void close_dict(FILE *fp) {
    puts("Close dict");
    if(fp) {
        flock(fileno(fp), LOCK_UN);
        fclose(fp);
    }
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
                        if(bind_server(port, times)) if(listen_socket(times)) accept_client();
                    } else printf("Error opening dict file: %s\n", argv[as_daemon?4:3]);
                } else puts("Start daemon error");
            } else printf("Error times: %d\n", times);
        } else printf("Error port: %d\n", port);
    }
    close(fd);
    exit(EXIT_FAILURE);
}
