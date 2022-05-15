#ifndef _SERVER_H_
#define _SERVER_H_

#include <stdint.h>

#define THREADCNT  32
#define MAXWAITSEC 8

// DICTPOOLBIT must be lower than 4*8 = 32
#define DICTPOOLBIT 16

enum server_cmd_t {CMDGET, CMDCAT, CMDMD5, CMDACK, CMDEND, CMDSET, CMDDEL, CMDDAT};
enum server_ack_t {ACKNONE=0b0000011, ACKSUCC=0b0010011, ACKDATA=0b0100011, ACKNULL=0b0110011, ACKNEQU=0b1000011, ACKERRO=0b1010011};

typedef enum server_cmd_t server_cmd_t;
typedef enum server_ack_t server_ack_t;

struct cmdpacket_t {
    uint8_t cmd;       // SERVERCMD or SERVERACK
    uint8_t datalen;   // data len is less than 255
    uint8_t md5[16];   // md5 digest of data below
    uint8_t data[];    // with TEA encoding, 64 bytes will be 160 bytes
};
typedef struct cmdpacket_t* cmdpacket_t;

#define CMDPACKET_HEAD_LEN (1+1+16)
#define CMDPACKET_LEN_MAX (CMDPACKET_HEAD_LEN+255)

#endif /* _SERVER_H_ */
