#ifndef _DICT_H_
#define _DICT_H_

#include <stdint.h>

#define ITEMSZ 64
struct DICT {
    char key[ITEMSZ];
    char data[ITEMSZ];
};
typedef struct DICT DICT;
#define DICTSZ sizeof(DICT)

#define LOCK_UN 0x00
#define LOCK_SH 0x01
#define LOCK_EX 0x02

int fill_md5();
uint32_t last_nonnull(char* p, uint32_t max_size);
int init_dict(char* file_path);
FILE *open_dict(uint8_t lock_type, uint32_t index);
void close_dict(uint8_t lock_type);
FILE* get_dict_fp(uint32_t index);
off_t get_dict_size();
int is_md5_equal(uint8_t* digest);

#endif