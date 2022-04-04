#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <simplecrypto.h>
#include <pthread.h>
#include "dict.h"
#include "server.h"

static pthread_rwlock_t mu;
static int lock;
static char* filepath;
static uint8_t dict_md5[16];

static FILE* fp = NULL;     //fp for EX
static FILE* fp5 = NULL;    //fp for md5
static FILE* thread_fp[THREADCNT];

#ifdef CPUBIT64
    #define _dict_md5_2 ((uint64_t*)&dict_md5)
#else
    #define _dict_md5_4 ((uint32_t*)&dict_md5)
#endif

int fill_md5() {
    size_t size = get_dict_size();
    if(!size) {
        memset(dict_md5, 0, 16);
        puts("Dict is empty, use all zero md5");
        return 1;
    }
    uint8_t* dict_buff = (uint8_t*)malloc(size);
    if(dict_buff) {
        pthread_rwlock_rdlock(&mu);
        rewind(fp5);
        if(fread(dict_buff, size, 1, fp5) == 1) {
            pthread_rwlock_unlock(&mu);
            md5(dict_buff, size, dict_md5);
            free(dict_buff);
            return 1;
        } else {
            pthread_rwlock_unlock(&mu);
            free(dict_buff);
            puts("Read dict error");
            return 0;
        }
    } else {
        puts("Allocate memory error");
        return 0; 
    }
}

int init_dict(char* file_path) {
    fp = fopen(file_path, "rb+");
    fp5 = fopen(file_path, "rb");
    if(fp) {
        int err = pthread_rwlock_init(&mu, NULL);
        if(err) {
            puts("Init lock error");
            return 0;
        }
        lock = DICT_LOCK_UN;
        filepath = file_path;
        return fill_md5();
    } else {
        puts("Open dict error");
        return 0;
    }
}

FILE* open_dict(uint8_t lock_type, uint32_t index) {
    if(lock_type & DICT_LOCK_EX) {
        pthread_rwlock_wrlock(&mu);
        lock |= DICT_LOCK_EX;
        if(!fp) fp = fopen(filepath, "rb+");
        else rewind(fp);
        return fp;
    }
    if(index >= THREADCNT) {
        puts("Open dict: Index out of bounds");
        return NULL;
    }
    pthread_rwlock_rdlock(&mu);
    lock |= DICT_LOCK_SH;
    if(!thread_fp[index]) thread_fp[index] = fopen(filepath, "rb");
    else rewind(thread_fp[index]);
    return thread_fp[index];
}

FILE* get_dict_fp_wr() {
    if(lock & DICT_LOCK_EX) return fp;
    return NULL;
}

FILE* get_dict_fp_rd() {
    rewind(fp5);
    return fp5;
}

void close_dict(uint8_t lock_type, uint32_t index) {
    if(lock_type & DICT_LOCK_EX) fflush(fp);
    lock &= ~lock_type;
    pthread_rwlock_unlock(&mu);
    puts("Close dict");
}

off_t get_dict_size() {
    struct stat statbuf;
    pthread_rwlock_rdlock(&mu);
    if(stat(filepath, &statbuf)==0) {
        pthread_rwlock_unlock(&mu);
        return statbuf.st_size;
    }
    pthread_rwlock_unlock(&mu);
    return -1;
}

int is_md5_equal(uint8_t* digest) {
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
