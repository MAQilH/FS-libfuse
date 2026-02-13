#ifndef COMMANDS_H
#define COMMANDS_H

#include "types.h"
#include "files.h"
#include "users.h"
#include "permissions.h"
#include "metadata.h"
#include "alloc.h"

// Command handlers
void cmd_chmod(const char *path, const char *mode);
void cmd_chown(const char *path, const char *user_group);
void cmd_chgrp(const char *path, const char *groupname);
void cmd_getfacl(const char *path);
void cmd_useradd(const char *username);
void cmd_userdel(const char *username);
void cmd_groupadd(const char *groupname);
void cmd_groupdel(const char *groupname);
void cmd_usermod(const char *username, const char *groupname);
void cmd_stressTest(void);
void fs_stats(void);
void get_file_stat(void);

#endif // COMMANDS_H
