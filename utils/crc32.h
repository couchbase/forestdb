#ifndef _JSAHN_CRC32_H
#define _JSAHN_CRC32_H

#ifdef __cplusplus
extern "C" {
#endif

uint32_t crc32_1(void* data, size_t len, uint32_t prev_value);
uint32_t crc32_8(void* data, size_t len, uint32_t prev_value);
uint32_t crc32_8_last8(void *data, size_t len, uint32_t prev_value);

#ifdef __cplusplus
}
#endif

#endif
