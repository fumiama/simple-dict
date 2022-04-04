#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdint.h>

#define THREADCNT 16
#define MAXWAITSEC 10

// DICTPOOLBIT must be lower than 4*8 = 32
#define DICTPOOLBIT 16

enum SERVERCMD {CMDGET, CMDCAT, CMDMD5, CMDACK, CMDEND, CMDSET, CMDDEL, CMDDAT};

struct CMDPACKET {
    uint8_t cmd;
    uint8_t datalen;   // data len is less than 255
    uint8_t md5[16];   // md5 digest of data below
    uint8_t data[];    // with TEA encoding, 64 bytes will be 160 bytes
};
typedef struct CMDPACKET CMDPACKET;

#define CMDPACKET_HEAD_LEN (1+1+16)
#define CMDPACKET_LEN_MAX (CMDPACKET_HEAD_LEN+255)

#endif /* _SERVER_H_ */
