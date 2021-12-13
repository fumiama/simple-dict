#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <simplecrypto.h>
#include "dict.h"
#include "server.h"

static uint8_t lock = 0;
static char* filepath;
static uint8_t* dict_md5;

static FILE* fp = NULL;     //fp for EX
static FILE* fp5 = NULL;    //fp for md5
static FILE* thread_fp[THREADCNT];

#ifdef CPUBIT64
    #define _dict_md5_2 ((uint64_t*)dict_md5)
#else
    #define _dict_md5_4 ((uint32_t*)dict_md5)
#endif

int fill_md5() {
    size_t size = get_dict_size();
    if(!size) {
        if(dict_md5) free(dict_md5);
        dict_md5 = malloc(16);
        memset(dict_md5, 0, 16);
        puts("Dict is empty, use all zero md5");
        return 1;
    }
    uint8_t* dict_buff = (uint8_t*)malloc(size);
    if(dict_buff) {
        rewind(fp5);
        if(fread(dict_buff, size, 1, fp5) == 1) {
            if(dict_md5) free(dict_md5);
            dict_md5 = md5(dict_buff, size);
            free(dict_buff);
            return 1;
        } else {
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
        lock = DICT_LOCK_UN;
        filepath = file_path;
        return fill_md5();
    } else {
        puts("Open dict error");
        return 0;
    }
}

#define _open_dict(p)\
    if(p) {\
        lock |= lock_type;\
        rewind(p);\
        return p;\
    } else {\
        puts("Open dict error");\
        return NULL;\
    }

FILE* open_dict(uint8_t lock_type, uint32_t index) {
    if(lock & DICT_LOCK_EX) return NULL;
    else if(lock_type & DICT_LOCK_EX) {
        if(!fp) fp = fopen(filepath, "rb+");
        _open_dict(fp);
    } else if(index < THREADCNT) {
        if(!thread_fp[index]) thread_fp[index] = fopen(filepath, "rb");
        _open_dict(thread_fp[index]);
    } else {
        puts("Index out of bounds");
        return NULL;
    }
}

FILE* get_dict_fp(uint32_t index) {
    if(lock & DICT_LOCK_EX) return fp;
    else if(lock & DICT_LOCK_SH && index < THREADCNT) return thread_fp[index];
    else return NULL;
}

void close_dict(uint8_t lock_type, uint32_t index) {
    puts("Close dict");
    lock &= ~lock_type;
    if(lock_type & DICT_LOCK_EX) fflush(fp);
    else fflush(thread_fp[index]);
}

off_t get_dict_size() {
    struct stat statbuf;
    if(stat(filepath, &statbuf)==0) return statbuf.st_size;
    else return -1;
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
