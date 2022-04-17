#ifndef _DICT_H_
#define _DICT_H_

#include <stdint.h>

#define DICTKEYSZ 127
#define DICTDATSZ 127
struct DICT {
    char key[DICTKEYSZ];
    char data[DICTDATSZ];
};
typedef struct DICT DICT;
#define DICTSZ sizeof(DICT)

#define DICT_LOCK_UN 0x00
#define DICT_LOCK_SH 0x01
#define DICT_LOCK_EX 0x02
#define DICT_LOCKING_EX 0x04

void  close_dict(uint8_t lock_type, uint32_t index, pthread_rwlock_t* mu);
int   fill_md5(pthread_rwlock_t* mu);
int   init_dict(char* file_path, pthread_rwlock_t* mu);
int   is_md5_equal(uint8_t* digest);
FILE* get_dict_fp_rd();
FILE* get_dict_fp_wr();
off_t get_dict_size();
FILE* open_dict(uint8_t lock_type, uint32_t index, pthread_rwlock_t* mu);

#endif