#ifndef _JSAHN_CRC32_H
#define _JSAHN_CRC32_H

uint32_t crc32_1(const void* data, size_t len, uint32_t prev_value);
uint32_t crc32_8(const void* data, size_t len, uint32_t prev_value);

#endif
