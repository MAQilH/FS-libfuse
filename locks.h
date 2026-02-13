#ifndef LOCKS_H
#define LOCKS_H

#include "types.h"

// File system locking functions
int fs_lock(void);
void fs_unlock(void);
int fs_lock_read(void);
void fs_unlock_read(void);

#endif // LOCKS_H
