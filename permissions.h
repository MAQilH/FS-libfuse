#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include "types.h"
#include "users.h"

// Permission management functions
int check_permission(FileEntry *entry, char operation);
uint32_t parse_permissions(const char *mode);
void format_permissions(uint32_t perm, char *output);

#endif // PERMISSIONS_H
