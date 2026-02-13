#ifndef USER_COMMANDS_H
#define USER_COMMANDS_H

#include "types.h"

// User management commands
void cmd_useradd(const char *username);
void cmd_userdel(const char *username);
void cmd_usermod(const char *username, const char *groupname);

#endif // USER_COMMANDS_H
