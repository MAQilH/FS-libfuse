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

// Dirent operations
int is_dirent(FileEntry *e);
uint32_t create_dirent(const char *name, uint32_t parent_offset);
int read_dirent(uint32_t dirent_offset, DirentData *out);
int dirent_add_child(uint32_t dirent_offset, uint32_t child_offset);
int dirent_remove_child(uint32_t dirent_offset, uint32_t child_offset);

// Path resolution
int resolve_path(const char *path, uint32_t cwd_offset, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset);
int resolve_absolute_path(const char *path, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset);
int resolve_relative_path(const char *path, uint32_t cwd_offset, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset);
int find_file_by_path(const char *path, uint32_t cwd_offset, FileEntry *out, uint32_t *offset_out);

// File copy and move operations
int fs_cp(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose);
int fs_mv(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose);

// Get current directory path
void get_current_directory_path(uint32_t cwd_offset, char *path, size_t path_size);

#endif // FILES_H
