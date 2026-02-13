#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>
#include <signal.h>

#ifdef ENABLE_PROFILING
#include "simple_profiler.h"
#define PROFILE_FUNC_START(name) PROF_START(name)
#define PROFILE_FUNC_STOP(name) PROF_END(name)
#else
#define PROFILE_FUNC_START(name)
#define PROFILE_FUNC_STOP(name)
#endif

#ifdef TRACY_ENABLE
#include "tracy_lib/public/tracy/TracyC.h"
#define PROFILE_FUNC() TracyCZone(___tracy_ctx, 1)
#define PROFILE_FUNC_END() TracyCZoneEnd(___tracy_ctx)
#define PROFILE_ZONE_N(name) TracyCZoneN(___tracy_ctx_##name, #name, 1)
#define PROFILE_ZONE_END_N(name) TracyCZoneEnd(___tracy_ctx_##name)
#define PROFILE_ALLOC(ptr, size) TracyCAlloc(ptr, size)
#define PROFILE_FREE(ptr) TracyCFree(ptr)
#define PROFILE_FRAME() TracyCFrameMark
#else
#define PROFILE_FUNC()
#define PROFILE_FUNC_END()
#define PROFILE_ZONE_N(name)
#define PROFILE_ZONE_END_N(name)
#define PROFILE_ALLOC(ptr, size)
#define PROFILE_FREE(ptr)
#define PROFILE_FRAME()
#endif

#define FS_FILENAME "filesys.db"
#define FS_SIZE     (32*1024*4096)
#define BLOCK_SIZE  4096

#define MAGIC_NUMBER 0xDEADBEEF

#define BITMAP_BLOCK 1
#define DATA_START_BLOCK 2
#define TOTAL_BLOCKS (FS_SIZE / BLOCK_SIZE)
#define BITMAP_SIZE (TOTAL_BLOCKS / 8)

#define CREATE  1
#define WRITE   2

#define MAX_GROUP_MEMBERS 16

// File types
#define FILE_TYPE_REGULAR 0
#define FILE_TYPE_DIRENT  1

// Dirent configuration
#define MAX_DIRENT_CHILDREN 128

#define STRESS_TEST_NUM_FILES      1000
#define STRESS_TEST_NUM_OPERATIONS 50000

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint32_t last_block;
	uint32_t data_start;
	uint32_t freelist_head;
	uint32_t files_head;  // Deprecated - kept for migration compatibility
	uint32_t root_dirent_offset;  // Offset to root dirent FileEntry
	uint32_t users_head;
	uint32_t groups_head;
	uint32_t next_uid;
	uint32_t next_gid;
} Metadata;

typedef struct FreeBlock {
	uint32_t first_block;
	uint32_t last_block;
	uint32_t next;
} FreeBlock;

typedef struct FileEntry {
	char     name[32];
	uint32_t size;
	uint32_t start;
	uint32_t permission;
	uint32_t type;
	uint32_t owner_uid;
	uint32_t owner_gid;
	uint32_t next;
} FileEntry;

typedef struct {
	FileEntry entry;
	int can_write;
	int open;
	uint32_t offset_in_fs;
} FSHandle;

typedef struct User {
	char username[32];
	char password[32];
	uint32_t uid;
	uint32_t gid;
	uint32_t next;
} User;

typedef struct Group {
	char groupname[32];
	uint32_t gid;
	uint32_t members[MAX_GROUP_MEMBERS];
	uint32_t member_count;
	uint32_t next;
} Group;

typedef struct {
	uint32_t current_uid;
	char current_username[32];
	int logged_in;
} UserSession;

// Dirent data structure - stores child file addresses
typedef struct {
	uint32_t child_count;
	uint32_t children[MAX_DIRENT_CHILDREN];  // Array of FileEntry offsets
} DirentData;

// Global variable declarations
extern Metadata meta;
extern FILE *disk;
extern FSHandle current_handle;
extern UserSession session;
extern uint32_t cwd_offset;

#endif // TYPES_H
