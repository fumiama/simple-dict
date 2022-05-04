#ifndef _DICT_H_
#define _DICT_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <simplecrypto.h>
#include <pthread.h>
#include "dict.h"
#include "server.h"

#define DICTKEYSZ 127
#define DICTDATSZ 127
struct dict_t {
    char key[DICTKEYSZ];
    char data[DICTDATSZ];
};
typedef struct dict_t dict_t;
#define DICTSZ sizeof(dict_t)

static char* dict_filepath;
static uint8_t dict_md5[16];

static volatile int is_ex_dict_open;

static FILE* dict_fp = NULL;     //fp for EX
static FILE* dict_fp_read = NULL;    //fp for md5
static FILE* dict_thread_fp[THREADCNT];
static pthread_rwlock_t mu;


#ifdef CPUBIT64
    #define _dict_md5_2 ((uint64_t*)&dict_md5)
#else
    #define _dict_md5_4 ((uint32_t*)&dict_md5)
#endif

static off_t get_dict_size() {
    struct stat statbuf;
    if(stat(dict_filepath, &statbuf)==0) {
        return statbuf.st_size;
    }
    return -1;
}

static int fill_md5(pthread_rwlock_t* mu) {
    size_t size = get_dict_size();
    if(!size) {
        memset(dict_md5, 0, 16);
        puts("Dict is empty, use all zero md5");
        return 0;
    }
    uint8_t* dict_buff = (uint8_t*)malloc(size);
    if(dict_buff) {
        if(pthread_rwlock_tryrdlock(mu)) {
            perror("Readlock busy");
            return 1;
        }
        rewind(dict_fp_read);
        if(fread(dict_buff, size, 1, dict_fp_read) == 1) {
            pthread_rwlock_unlock(mu);
            md5(dict_buff, size, dict_md5);
            free(dict_buff);
            return 0;
        } else {
            pthread_rwlock_unlock(mu);
            free(dict_buff);
            perror("Read dict error");
            return 2;
        }
    } else {
        perror("Allocate memory error");
        return 3; 
    }
}

static int init_dict(char* file_path, pthread_rwlock_t* mu) {
    dict_fp = fopen(file_path, "rb+");
    dict_fp_read = fopen(file_path, "rb");
    if(dict_fp) {
        int err = pthread_rwlock_init(mu, NULL);
        if(err) {
            perror("Init lock error");
            return 1;
        }
        dict_filepath = file_path;
        return fill_md5(mu);
    }
    perror("Open dict error");
    return 2;
}

static inline FILE* open_ex_dict() {
    if(pthread_rwlock_wrlock(&mu)) {
        perror("Open dict: Writelock busy");
        return NULL;
    }
    if(!dict_fp) dict_fp = fopen(dict_filepath, "rb+");
    else rewind(dict_fp);
    if(dict_fp) is_ex_dict_open = 1;
    return dict_fp;
}

static inline FILE* open_shared_dict(uint32_t index) {
    if(index >= THREADCNT) {
        puts("Open dict: Index out of bounds");
        return NULL;
    }
    if(pthread_rwlock_tryrdlock(&mu)) {
        perror("Open dict: Readlock busy");
        return NULL;
    }
    if(!dict_thread_fp[index]) dict_thread_fp[index] = fopen(dict_filepath, "rb");
    else rewind(dict_thread_fp[index]);
    return dict_thread_fp[index];
}

static FILE* get_dict_fp_wr() {
    return dict_fp;
}

static FILE* get_dict_fp_rd() {
    rewind(dict_fp_read);
    return dict_fp_read;
}

static inline void close_ex_dict() {
    fflush(dict_fp);
    is_ex_dict_open = 0;
    pthread_rwlock_unlock(&mu);
    puts("Close ex dict");
}

static inline void close_shared_dict() {
    pthread_rwlock_unlock(&mu);
    puts("Close shared dict");
}

static inline int is_dict_md5_equal(uint8_t* digest) {
    #ifdef CPUBIT64
        uint64_t* digest2 = (uint64_t*)digest;
        return (digest2[0] == _dict_md5_2[0]) &&
                (digest2[1] == _dict_md5_2[1]);
    #else
        uint32_t* digest4 = (uint32_t*)digest;
        return (digest4[0] == _dict_md5_4[0]) &&
                (digest4[1] == _dict_md5_4[1]) &&
                (digest4[2] == _dict_md5_4[2]) &&
                (digest4[3] == _dict_md5_4[3]);
    #endif
}

#endif