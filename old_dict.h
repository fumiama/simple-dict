#ifndef _OLD_DICT_H_
#define _OLD_DICT_H_

#include <stdint.h>
#define DATASIZE 64
struct DICTBLK{
    char key[(DATASIZE-1)];
    uint8_t keysize;
    char data[(DATASIZE-1)];
    uint8_t datasize;
};
typedef struct DICTBLK DICTBLK;
#define DICTBLKSZ sizeof(DICTBLK)

#endif
