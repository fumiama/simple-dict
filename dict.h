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

static volatile int has_dict_opened;
static volatile int is_dict_opening;
static volatile uint32_t dict_owner_index = (uint32_t)-1;

static FILE* dict_fp = NULL;
static pthread_rwlock_t mu;

#ifdef CPUBIT64
    #define _dict_md5_2 ((uint64_t*)&dict_md5)
#else
    #define _dict_md5_4 ((uint32_t*)&dict_md5)
#endif

static inline off_t get_dict_size() {
    struct stat statbuf;
    if(stat(dict_filepath, &statbuf)==0) {
        return statbuf.st_size;
    }
    return -1;
}

static int fill_md5(FILE* fp) {
    size_t size = get_dict_size();
    if(!size) {
        memset(dict_md5, 0, 16);
        puts("Dict is empty, use all zero md5");
        return 0;
    }
    uint8_t* dict_buff = (uint8_t*)malloc(size);
    if(dict_buff) {
        if(fread(dict_buff, size, 1, fp) == 1) {
            md5(dict_buff, size, dict_md5);
            free(dict_buff);
            return 0;
        } else {
            free(dict_buff);
            perror("Read dict error");
            return 2;
        }
    } else {
        perror("Allocate memory error");
        return 3; 
    }
}

static int init_dict(char* file_path) {
    FILE* fp = fopen(file_path, "rb+");
    if(fp) {
        int err = pthread_rwlock_init(&mu, NULL);
        if(err) {
            perror("Init lock error");
            return 1;
        }
        dict_filepath = file_path;
        err = fill_md5(fp);
        fclose(fp);
        return err;
    }
    perror("Open dict error");
    return 2;
}

static inline FILE* open_dict(uint32_t index, int isro) {
    is_dict_opening = 1;
    if(pthread_rwlock_wrlock(&mu)) {
        perror("Open dict: Writelock busy");
        is_dict_opening = 0;
        return NULL;
    }
    is_dict_opening = 0;
    dict_fp = fopen(dict_filepath, isro?"rb":"rb+");
    if(!dict_fp) {
        perror("Open dict: fopen");
        pthread_rwlock_unlock(&mu);
        return NULL;
    }
    has_dict_opened = 1;
    dict_owner_index = index;
    puts("Open dict");
    return dict_fp;
}

static inline int require_shared_lock() {
    if(pthread_rwlock_tryrdlock(&mu)) {
        perror("Open dict: Readlock busy");
        return 1;
    }
    puts("Shared lock required");
    return 0;
}

static inline void release_shared_lock() {
    pthread_rwlock_unlock(&mu);
    puts("Release shared lock");
}

static inline void close_dict(uint32_t index) {
    if(index != dict_owner_index) return;
    if(has_dict_opened) {
        fclose(dict_fp);
        dict_fp = NULL;
        has_dict_opened = 0;
        dict_owner_index = (uint32_t)-1;
        pthread_rwlock_unlock(&mu);
        puts("Close dict");
    } else puts("Dict already closed");
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