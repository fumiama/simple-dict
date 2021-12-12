#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"

//#define DEBUG

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

void init_crypto() {
    srand(time(NULL));
}

void reset_seq(int index) {
    seqs[index] = 0;
}

char* raw_encrypt(const char* buf, off_t* len, int index, const char pwd[64]) {
    TEADAT tin = {*len, (uint8_t*)buf};
    TEA tea[4];

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index]++;
    TEADAT* tout = tea_encrypt_native_endian(tea, sumtable, &tin);

    *len = tout->len;
    char* encbuf = (char*)malloc(*len);
    memcpy(encbuf, tout->data, *len);
    free(tout->ptr);
    free(tout);

    return encbuf;
}

char* raw_decrypt(const char* buf, off_t* len, int index, const char pwd[64]) {
    TEADAT tin = {*len, (uint8_t*)buf};
    TEA tea[4];

    ((uint64_t*)tea)[0] = ((uint64_t*)pwd)[0];
    ((uint64_t*)tea)[1] = ((uint64_t*)pwd)[1];
    ((uint8_t*)tea)[15] = seqs[index];
    TEADAT* tout = tea_decrypt_native_endian(tea, sumtable, &tin);
    if(!tout) return NULL;
    else seqs[index]++;

    *len = tout->len;
    char* decbuf = (char*)malloc(*len);
    memcpy(decbuf, tout->data, *len);
    free(tout->ptr);
    free(tout);

    return decbuf;
}

void cmdpacket_encrypt(CMDPACKET* p, int index, const char pwd[64]) {
    TEADAT tin = {p->datalen, p->data};
    TEA tea[4];
    #ifdef DEBUG
        printf("encrypt len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
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

    TEADAT* tout = tea_encrypt_native_endian(tea, sumtable, &tin);

    uint8_t* datamd5 = md5(p->data, p->datalen);
    #ifdef DEBUG
        printf("encrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", datamd5[i]);
        putchar('\n');
    #endif
    memcpy(p->md5, datamd5, 16);
    free(datamd5);

    p->datalen = tout->len;
    memcpy(p->data, tout->data, p->datalen);
    #ifdef DEBUG
        printf("encrypted data len: %d, data: ", p->datalen);
        for(int i = 0; i < p->datalen; i++) printf("%02x", p->data[i]);
        putchar('\n');
    #endif
    free(tout->ptr);
    free(tout);

    return;
}

int cmdpacket_decrypt(CMDPACKET* p, int index, const char pwd[64]) {
    TEADAT tin = {p->datalen, p->data};
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

    TEADAT* tout = tea_decrypt_native_endian(tea, sumtable, &tin);
    if(!tout) return 0;

    uint8_t* datamd5 = md5(tout->data, tout->len);
    #ifdef DEBUG
        printf("decrypt md5: ");
        for(int i = 0; i < 16; i++) printf("%02x", datamd5[i]);
        putchar('\n');
        printf("decrypted data len: %d, data: ", tout->len);
        for(int i = 0; i < tout->len; i++) printf("%02x", tout->data[i]);
        putchar('\n');
    #endif
    if(is_md5_equal(datamd5, p->md5)) {
        seqs[index]++;
        p->datalen = tout->len;
        memcpy(p->data, tout->data, p->datalen);
        free(datamd5);
        free(tout->ptr);
        free(tout);
        return 1;
    }
    free(datamd5);
    free(tout->ptr);
    free(tout);
    return 0;
}
