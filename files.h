#ifndef FILES_H
#define FILES_H

#include "types.h"
#include "locks.h"
#include "metadata.h"
#include "alloc.h"
#include "permissions.h"
#include "users.h"
#include "bitmap.h"

// File operations
int find_file(const char *name, FileEntry *out, uint32_t *offset_out);
uint32_t append_file_entry(FileEntry *e);
FSHandle fs_open(const char *name, int flags, int verbose);
int fs_read(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
int fs_write(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
void fs_shrink(FSHandle *h, uint32_t new_size, int verbose);
void fs_rm(const char *name, int verbose);
void fs_close(FSHandle *h);
void update_file_entry(FSHandle *h);

// Wrapper functions for compatibility
FSHandle fs_open_impl(const char *name, int flags, int verbose);
int fs_read_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
int fs_write_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
void fs_rm_impl(const char *name, int verbose);
void fs_shrink_impl(FSHandle *h, uint32_t new_size, int verbose);

#endif // FILES_H
