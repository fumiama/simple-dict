#include <stdio.h>
#include <sys/stat.h>
#include "dict.h"

static FILE *fp = NULL;
static int lock = 0;
static char* filepath;

uint32_t last_nonnull(char* p, uint32_t max_size) {
    if(max_size > 1) while(!p[max_size - 1]) max_size--;
    return max_size;
}

int init_dict(char* file_path) {
    fp = fopen(file_path, "rb+");
    if(fp) {
        lock = LOCK_UN;
        filepath = file_path;
        return 1;
    } else {
        puts("Open dict error");
        return 0;
    }
}

FILE *open_dict(int lock_type) {
    if(lock & LOCK_EX) return NULL;
    else {
        if(!fp) fp = fopen(filepath, "rb+");
        if(fp) {
            lock = lock_type;
            rewind(fp);
            return fp;
        } else {
            puts("Open dict error");
            return NULL;
        }
    }
}

void close_dict() {
    puts("Close dict");
    lock = LOCK_UN;
}

off_t get_dict_size() {
    struct stat statbuf;
    if(stat(filepath, &statbuf)==0) return statbuf.st_size;
    else return -1;
}
