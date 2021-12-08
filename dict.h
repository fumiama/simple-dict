#ifndef _DICT_H_
#define _DICT_H_

#include <stdint.h>

#define DICTKEYSZ  64
#define DICTDATSZ 64
struct DICT {
    char key[DICTKEYSZ];
    char data[DICTDATSZ];
};
typedef struct DICT DICT;
#define DICTSZ sizeof(DICT)

#define DICT_LOCK_UN 0x00
#define DICT_LOCK_SH 0x01
#define DICT_LOCK_EX 0x02

int init_dict(char* file_path);
void close_dict(uint8_t lock_type, uint32_t index);
int fill_md5();
FILE* get_dict_fp(uint32_t index);
off_t get_dict_size();
int is_md5_equal(uint8_t* digest);
FILE *open_dict(uint8_t lock_type, uint32_t index);

#endif