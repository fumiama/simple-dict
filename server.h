#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define THREADCNT 16
#define MAXWAITSEC 10

struct THREADTIMER {
    uint32_t index;
    time_t touch;
    int accept_fd;
    ssize_t numbytes;
    char *data;
    char status, lock_type;
};
typedef struct THREADTIMER THREADTIMER;

void accept_client();
void accept_timer(void *p);
int bind_server(uint16_t port, int try_times);
int check_buffer(THREADTIMER *timer);
int close_and_send(int accept_fd, char *data, size_t numbytes, uint32_t lock_type);
int free_after_send(int accept_fd, char *data, size_t length);
void handle_accept(void *accept_fd_p);
void handle_pipe(int signo);
void handle_quit(int signo);
void kill_thread(THREADTIMER* timer);
int listen_socket(int try_times);
int send_all(THREADTIMER *timer);
int send_data(int accept_fd, char *data, size_t length);
int sm1_pwd(THREADTIMER *timer);
int s0_init(THREADTIMER *timer);
int s1_get(THREADTIMER *timer);
int s2_set(THREADTIMER *timer);
int s3_set_data(THREADTIMER *timer);
int s4_del(THREADTIMER *timer);
int s5_md5(THREADTIMER *timer);

#endif