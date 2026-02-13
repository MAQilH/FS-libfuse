#ifndef FILE_COMMANDS_H
#define FILE_COMMANDS_H

#include "types.h"

// File attribute commands
void cmd_chmod(const char *path, const char *mode);
void cmd_chown(const char *path, const char *user_group);
void cmd_chgrp(const char *path, const char *groupname);
void cmd_getfacl(const char *path);

#endif // FILE_COMMANDS_H
