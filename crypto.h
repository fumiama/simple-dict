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

#ifndef CRYPTO_SUMTABLE
#define CRYPTO_SUMTABLE {\
	0x9e3579b9,\
	0x3c6ef172,\
	0xd2a66d2b,\
	0x78dd36e4,\
	0x17e5609d,\
	0xb54fda56,\
	0x5384560f,\
	0xf1bb77c8,\
	0x8ff24781,\
	0x2e4ac13a,\
	0xcc653af3,\
	0x6a9964ac,\
	0x08d12965,\
	0xa708081e,\
	0x451221d7,\
	0xe37793d0 \
}
#endif

// TEA encoding sumtable
static const uint32_t sumtable[0x10] = CRYPTO_SUMTABLE;

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
    TEA tea;

    ((uint64_t*)tea.t)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea.t)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea.t)[15] = seqs[index]++;

    int64_t dstlen = tea_encrypt_len(*len);
    char* encbuf = (char*)malloc(dstlen);
    if(!encbuf) return NULL;
    *len = tea_encrypt_native_endian(tea, sumtable, (const uint8_t*)buf, *len, (uint8_t*)encbuf);
    return encbuf;
}

// raw_decrypt buf: in->src out->dstptr
static char* raw_decrypt(const char* buf, off_t* len, int index, const char pwd[64], char** ptr) {
    TEA tea;

    ((uint64_t*)tea.t)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea.t)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea.t)[15] = seqs[index];

    char* decbuf = (char*)malloc(*len);
    if(!decbuf) return NULL;
    char* out = (char*)tea_decrypt_native_endian(tea, sumtable, (const uint8_t*)buf, *len, (uint8_t*)decbuf);
    if(!out) {
        free(decbuf);
        return NULL;
    }

    seqs[index]++;

    *len = tea_decrypt_len(*len, decbuf[0]);
    *ptr = decbuf;

    return out;
}

static int cmdpacket_encrypt(cmdpacket_t p, int index, const char pwd[64], const char* data) {
    TEA tea;
    #ifdef DEBUG
        printf("encrypt len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", data[i]);
        putchar('\n');
    #endif

    ((uint64_t*)tea.t)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea.t)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea.t)[15] = seqs[index]++;

    #ifdef DEBUG
        printf("encrypt tea: ");
        for(int i = 0; i < 16; i++) printf("%02x", ((uint8_t*)tea.t)[i]);
        putchar('\n');
    #endif

    int64_t outlen = tea_encrypt_len(p->datalen);

    char out[outlen];

    md5((const uint8_t *)data, p->datalen, p->md5);
    #ifdef DEBUG
        printf("encrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", p->md5[i]);
        putchar('\n');
    #endif

    p->datalen = tea_encrypt_native_endian(tea, sumtable, (const uint8_t*)data, p->datalen, (uint8_t*)out);
    memcpy(p->data, out, p->datalen);

    #ifdef DEBUG
        printf("encrypted data len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
        putchar('\n');
    #endif

    return 0;
}

static int cmdpacket_decrypt(cmdpacket_t p, int index, const char pwd[64]) {
    TEA tea;
    #ifdef DEBUG
        printf("decrypt len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
        putchar('\n');
    #endif

    ((uint64_t*)tea.t)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea.t)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea.t)[15] = seqs[index];

    #ifdef DEBUG
        printf("decrypt tea: ");
        for(int i = 0; i < 16; i++) printf("%02x", ((uint8_t*)tea.t)[i]);
        putchar('\n');
    #endif

    char outbuf[p->datalen];

    char* out = (char*)tea_decrypt_native_endian(tea, sumtable, (const uint8_t*)p->data, p->datalen, (uint8_t*)outbuf);
    if(!out) return 2;

    p->datalen = tea_decrypt_len(p->datalen, outbuf[0]);

    uint8_t datamd5[16];
    md5((const uint8_t*)out, p->datalen, datamd5);

    #ifdef DEBUG
        printf("decrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", datamd5[i]);
        putchar('\n');
        printf("decrypted data len: %u, data: ", (unsigned int)p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", out[i]);
        putchar('\n');
    #endif

    if(is_md5_equal((uint8_t*)datamd5, p->md5)) {
        seqs[index]++;
        memcpy(p->data, out, p->datalen);
        return 0;
    }

    return 3;
}

#endif /* _CRYPTO_H_ */
