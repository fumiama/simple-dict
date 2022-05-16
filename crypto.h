#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <simplecrypto.h>
#include <sys/types.h>
#include "server.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"

// TEA encoding sumtable
static const uint32_t sumtable[0x10] = {
	0x9e3579b9,
	0x3c6ef172,
	0xd2a66d2b,
	0x78dd36e4,
	0x17e5609d,
	0xb54fda56,
	0x5384560f,
	0xf1bb77c8,
	0x8ff24781,
	0x2e4ac13a,
	0xcc653af3,
	0x6a9964ac,
	0x08d12965,
	0xa708081e,
	0x451221d7,
	0xe37793d0,
};

static uint8_t seqs[THREADCNT]; // 消息序号

static inline int is_md5_equal(uint8_t* digest, uint8_t* digest2) {
    #ifdef CPUBIT64
        return (digest[0] == digest2[0]) &&
                (digest[1] == digest2[1]);
    #else
        return (digest[0] == digest2[0]) &&
                (digest[1] == digest2[1]) &&
                (digest[2] == digest2[2]) &&
                (digest[3] == digest2[3]);
    #endif
}

static void init_crypto() {
    srand(time(NULL));
}

static void reset_seq(int index) {
    seqs[index] = 0;
}

static char* raw_encrypt(const char* buf, off_t* len, int index, const char pwd[64]) {
    TEADAT tin = {*len, (uint8_t*)buf};
    TEADAT tout;
    TEA tea[4];

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index]++;
    tea_encrypt_native_endian(tea, sumtable, &tin, &tout);

    *len = tout.len;
    char* encbuf = (char*)malloc(*len);
    memcpy(encbuf, tout.data, *len);
    free(tout.ptr);

    return encbuf;
}

static char* raw_decrypt(const char* buf, off_t* len, int index, const char pwd[64]) {
    TEADAT tin = {*len, (uint8_t*)buf};
    TEADAT tout;
    TEA tea[4];

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index];
    if(!tea_decrypt_native_endian(tea, sumtable, &tin, &tout)) return NULL;
    else if(tout.len <= 0) {
        free(tout.ptr);
        return NULL;
    } else seqs[index]++;

    *len = tout.len;
    char* decbuf = (char*)malloc(*len);
    memcpy(decbuf, tout.data, *len);
    free(tout.ptr);

    return decbuf;
}

static void cmdpacket_encrypt(cmdpacket_t p, int index, const char pwd[64], const char* data) {
    TEADAT tin = {p->datalen, (uint8_t *)data};
    TEADAT tout;
    TEA tea[4];
    #ifdef DEBUG
        printf("encrypt len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", data[i]);
        putchar('\n');
    #endif

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index]++;

    #ifdef DEBUG
        printf("encrypt tea: ");
        for(int i = 0; i < 16; i++) printf("%02x", ((uint8_t*)tea)[i]);
        putchar('\n');
    #endif

    tea_encrypt_native_endian(tea, sumtable, &tin, &tout);

    md5((const uint8_t *)data, p->datalen, p->md5);
    #ifdef DEBUG
        printf("encrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", p->md5[i]);
        putchar('\n');
    #endif

    p->datalen = tout.len;
    memcpy(p->data, tout.data, p->datalen);
    #ifdef DEBUG
        printf("encrypted data len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
        putchar('\n');
    #endif
    free(tout.ptr);

    return;
}

static int cmdpacket_decrypt(cmdpacket_t p, int index, const char pwd[64]) {
    TEADAT tin = {p->datalen, p->data};
    TEADAT tout;
    TEA tea[4];
    #ifdef DEBUG
        printf("decrypt len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
        putchar('\n');
    #endif

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index];

    #ifdef DEBUG
        printf("decrypt tea: ");
        for(int i = 0; i < 16; i++) printf("%02x", ((uint8_t*)tea)[i]);
        putchar('\n');
    #endif

    if(!tea_decrypt_native_endian(tea, sumtable, &tin, &tout)) return 0;
    if(tout.len <= 0) {
        free(tout.ptr);
        return 0;
    }
    uint8_t datamd5[16];
    md5(tout.data, tout.len, datamd5);
    #ifdef DEBUG
        printf("decrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", datamd5[i]);
        putchar('\n');
        printf("decrypted data len: %u, data: ", (unsigned int)tout.len);
        for(int i = 0; i < tout.len; i++) printf("%02x", tout.data[i]);
        putchar('\n');
    #endif
    if(is_md5_equal((uint8_t*)datamd5, p->md5)) {
        seqs[index]++;
        p->datalen = tout.len;
        memcpy(p->data, tout.data, p->datalen);
        free(tout.ptr);
        return 1;
    }
    free(tout.ptr);
    return 0;
}


#endif /* _CRYPTO_H_ */
