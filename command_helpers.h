#ifndef COMMAND_HELPERS_H
#define COMMAND_HELPERS_H

#include "types.h"
#include "files.h"
#include "users.h"
#include "metadata.h"

// Validation helpers
int check_logged_in(void);
int check_root_required(void);

// File operation helpers
int find_file_with_validation(const char *path, FileEntry *out, uint32_t *offset_out);
int check_file_ownership(const FileEntry *e, const char *path);
void update_file_entry_at_offset(uint32_t offset, const FileEntry *e);

// User/group operation helpers
int user_owns_files(uint32_t uid);
void remove_user_from_all_groups(uint32_t uid);
void remove_from_user_list(uint32_t offset);
void remove_from_group_list(uint32_t offset);

#endif // COMMAND_HELPERS_H
