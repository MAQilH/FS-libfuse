#ifndef USERS_H
#define USERS_H

#include "types.h"
#include "locks.h"
#include "metadata.h"
#include "alloc.h"

// User and group management functions
int find_user(const char *username, User *out, uint32_t *offset_out);
int find_user_by_uid(uint32_t uid, User *out);
int find_group(const char *groupname, Group *out, uint32_t *offset_out);
int find_group_by_gid(uint32_t gid, Group *out);
uint32_t append_user(User *u);
uint32_t append_group(Group *g);
void initialize_root_user(void);
int user_in_group(uint32_t uid, uint32_t gid);
int authenticate_user(const char *username, const char *password);
int login_user(const char *username, const char *password);
int su_user(const char *username);
uint32_t get_current_uid(void);
int is_root(void);

#endif // USERS_H
