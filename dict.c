#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <simplecrypto.h>
#include <pthread.h>
#include "dict.h"
#include "server.h"

static char* filepath;
static uint8_t dict_md5[16];

static FILE* fp = NULL;     //fp for EX
static FILE* fp_read = NULL;    //fp for md5
static FILE* thread_fp[THREADCNT];

#ifdef CPUBIT64
    #define _dict_md5_2 ((uint64_t*)&dict_md5)
#else
    #define _dict_md5_4 ((uint32_t*)&dict_md5)
#endif

int fill_md5(pthread_rwlock_t* mu) {
    size_t size = get_dict_size(mu);
    if(!size) {
        memset(dict_md5, 0, 16);
        puts("Dict is empty, use all zero md5");
        return 1;
    }
    uint8_t* dict_buff = (uint8_t*)malloc(size);
    if(dict_buff) {
        if(pthread_rwlock_tryrdlock(mu)) {
            puts("Readlock busy");
            return 0;
        }
        rewind(fp_read);
        if(fread(dict_buff, size, 1, fp_read) == 1) {
            pthread_rwlock_unlock(mu);
            md5(dict_buff, size, dict_md5);
            free(dict_buff);
            return 1;
        } else {
            pthread_rwlock_unlock(mu);
            free(dict_buff);
            puts("Read dict error");
            return 0;
        }
    } else {
        puts("Allocate memory error");
        return 0; 
    }
}

int init_dict(char* file_path, pthread_rwlock_t* mu) {
    fp = fopen(file_path, "rb+");
    fp_read = fopen(file_path, "rb");
    if(fp) {
        int err = pthread_rwlock_init(mu, NULL);
        if(err) {
            puts("Init lock error");
            return 0;
        }
        filepath = file_path;
        return fill_md5(mu);
    }
    puts("Open dict error");
    return 0;
}

FILE* open_dict(uint8_t lock_type, uint32_t index, pthread_rwlock_t* mu) {
    if(lock_type & DICT_LOCK_EX) {
        if(pthread_rwlock_trywrlock(mu)) {
            puts("Open dict: Writelock busy");
            return NULL;
        }
        if(!fp) fp = fopen(filepath, "rb+");
        else rewind(fp);
        return fp;
    }
    if(index >= THREADCNT) {
        puts("Open dict: Index out of bounds");
        return NULL;
    }
    if(pthread_rwlock_tryrdlock(mu)) {
        puts("Open dict: Readlock busy");
        return NULL;
    }
    if(!thread_fp[index]) thread_fp[index] = fopen(filepath, "rb");
    else rewind(thread_fp[index]);
    return thread_fp[index];
}

FILE* get_dict_fp_wr() {
    return fp;
}

FILE* get_dict_fp_rd() {
    rewind(fp_read);
    return fp_read;
}

void close_dict(uint8_t lock_type, uint32_t index, pthread_rwlock_t* mu) {
    if(lock_type & DICT_LOCK_EX) fflush(fp);
    pthread_rwlock_unlock(mu);
    puts("Close dict");
}

off_t get_dict_size() {
    struct stat statbuf;
    if(stat(filepath, &statbuf)==0) {
        return statbuf.st_size;
    }
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
