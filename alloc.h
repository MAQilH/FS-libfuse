#ifndef ALLOC_H
#define ALLOC_H

#include "types.h"
#include "bitmap.h"
#include "metadata.h"

// Block allocation functions
uint32_t alloc(uint32_t size, int verbose);
void fs_free(uint32_t start, uint32_t size);
void freelist_add(uint32_t first, uint32_t last);
void freelist_remove(uint32_t offset);
void freelist_print(void);

#endif // ALLOC_H
