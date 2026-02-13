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

#define STRESS_TEST_NUM_FILES      1000
#define STRESS_TEST_NUM_OPERATIONS 50000

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint32_t last_block;
	uint32_t data_start;
	uint32_t freelist_head;
	uint32_t files_head;
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

Metadata meta;

FILE *disk = NULL;
FSHandle current_handle = {0};
UserSession session = {0};

static int global_fs_lock_fd = -1;
static int write_lock_count = 0;  // Reentrancy support for write locks
static int read_lock_count = 0;   // Reentrancy support for read locks
static pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;  // Protect lock counts

static int get_lock_timeout(void) {
	static int timeout = -1;
	if (timeout == -1) {
		const char *env_timeout = getenv("FS_LOCK_TIMEOUT");
		if (env_timeout) {
			timeout = atoi(env_timeout);
			if (timeout <= 0) timeout = 2;
		} else {
			timeout = 2;
		}
	}
	return timeout;
}

// Check if process with given PID exists
static int process_exists(pid_t pid) {
	if (pid <= 0) return 0;
	// Try to send signal 0 (doesn't actually send, just checks)
	return (kill(pid, 0) == 0 || errno != ESRCH);
}

// Clean up stale lock file if process doesn't exist
static void cleanup_stale_lock(void) {
	char lockfile[256];
	snprintf(lockfile, sizeof(lockfile), "%s.lock", FS_FILENAME);
	
	// Try to read PID from lock file (if we stored it)
	// For now, check if lock file exists and is locked
	int fd = open(lockfile, O_RDWR);
	if (fd >= 0) {
		struct flock lock;
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		
		// Try non-blocking check
		if (fcntl(fd, F_GETLK, &lock) == 0) {
			if (lock.l_type != F_UNLCK && lock.l_pid > 0) {
				if (!process_exists(lock.l_pid)) {
					// Process doesn't exist, try to remove stale lock
					lock.l_type = F_UNLCK;
					fcntl(fd, F_SETLK, &lock);
					if (getenv("FS_LOCK_DEBUG")) {
						fprintf(stderr, "[PID %d] Cleaned up stale lock from PID %d\n", 
							getpid(), lock.l_pid);
					}
				}
			}
		}
		close(fd);
	}
}

static int fs_lock_read(void) {
	pthread_mutex_lock(&lock_mutex);
	
	// Reentrancy: if we already have a write lock, we can read
	if (write_lock_count > 0) {
		read_lock_count++;
		pthread_mutex_unlock(&lock_mutex);
		return 0;
	}
	
	// Reentrancy: if we already have a read lock, increment count
	if (read_lock_count > 0) {
		read_lock_count++;
		pthread_mutex_unlock(&lock_mutex);
		return 0;
	}
	
	pthread_mutex_unlock(&lock_mutex);
	
	if (global_fs_lock_fd == -1) {
		char lockfile[256];
		snprintf(lockfile, sizeof(lockfile), "%s.lock", FS_FILENAME);
		global_fs_lock_fd = open(lockfile, O_CREAT | O_RDWR, 0666);
		if (global_fs_lock_fd == -1) {
			perror("Failed to open lock file");
			return -1;
		}
		fcntl(global_fs_lock_fd, F_SETFD, FD_CLOEXEC);
		cleanup_stale_lock();
	}
	
	struct flock lock;
	lock.l_type = F_RDLCK;  // Read lock instead of write lock
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	
	int timeout_sec = get_lock_timeout();
	time_t start_time = time(NULL);
	int retry_count = 0;
	
	while (1) {
		if (fcntl(global_fs_lock_fd, F_SETLK, &lock) == 0) {
			pthread_mutex_lock(&lock_mutex);
			read_lock_count++;
			pthread_mutex_unlock(&lock_mutex);
			
			if (retry_count > 0 && getenv("FS_LOCK_DEBUG")) {
				fprintf(stderr, "[PID %d] Read lock acquired after %d retries\n", getpid(), retry_count);
				fflush(stderr);
			}
			return 0;
		}
		
		retry_count++;
		
		time_t current_time = time(NULL);
		time_t elapsed = current_time - start_time;
		if (elapsed >= timeout_sec) {
			fprintf(stderr, "[PID %d] ERROR: Read lock timeout after %ld seconds!\n", 
				getpid(), elapsed);
			fflush(stderr);
			return -1;  // Return error instead of abort()
		}
		
		if (elapsed >= timeout_sec / 2 && retry_count % 10 == 0 && getenv("FS_LOCK_DEBUG")) {
			fprintf(stderr, "[PID %d] Waiting for read lock... (%ld/%d seconds)\n", 
				getpid(), elapsed, timeout_sec);
			fflush(stderr);
		}
		
		usleep(100000);
	}
}

static void fs_unlock_read(void) {
	pthread_mutex_lock(&lock_mutex);
	
	if (read_lock_count > 0) {
		read_lock_count--;
		if (read_lock_count == 0 && global_fs_lock_fd != -1) {
			struct flock lock;
			lock.l_type = F_UNLCK;
			lock.l_whence = SEEK_SET;
			lock.l_start = 0;
			lock.l_len = 0;
			fcntl(global_fs_lock_fd, F_SETLK, &lock);
		}
	}
	
	pthread_mutex_unlock(&lock_mutex);
}

static int fs_lock(void) {
	pthread_mutex_lock(&lock_mutex);
	
	// Reentrancy: if we already have a write lock, increment count
	if (write_lock_count > 0) {
		write_lock_count++;
		pthread_mutex_unlock(&lock_mutex);
		return 0;
	}
	
	pthread_mutex_unlock(&lock_mutex);
	
	if (global_fs_lock_fd == -1) {
		char lockfile[256];
		snprintf(lockfile, sizeof(lockfile), "%s.lock", FS_FILENAME);
		global_fs_lock_fd = open(lockfile, O_CREAT | O_RDWR, 0666);
		if (global_fs_lock_fd == -1) {
			perror("Failed to open lock file");
			return -1;
		}
		fcntl(global_fs_lock_fd, F_SETFD, FD_CLOEXEC);
		cleanup_stale_lock();
	}
	
	struct flock lock;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	
	int timeout_sec = get_lock_timeout();
	time_t start_time = time(NULL);
	int retry_count = 0;
	
	while (1) {
		if (fcntl(global_fs_lock_fd, F_SETLK, &lock) == 0) {
			pthread_mutex_lock(&lock_mutex);
			write_lock_count++;
			pthread_mutex_unlock(&lock_mutex);
			
			if (retry_count > 0 && getenv("FS_LOCK_DEBUG")) {
				fprintf(stderr, "[PID %d] Write lock acquired after %d retries\n", getpid(), retry_count);
				fflush(stderr);
			}
			return 0;
		}
		
		retry_count++;
		
		time_t current_time = time(NULL);
		time_t elapsed = current_time - start_time;
		if (elapsed >= timeout_sec) {
			fprintf(stderr, "[PID %d] ERROR: Write lock timeout after %ld seconds! Possible deadlock.\n", 
				getpid(), elapsed);
			fprintf(stderr, "[PID %d] Lock file: %s.lock (fd=%d)\n", getpid(), FS_FILENAME, global_fs_lock_fd);
			fprintf(stderr, "[PID %d] Retried %d times\n", getpid(), retry_count);
			fflush(stderr);
			return -1;  // Return error instead of abort()
		}
		
		if (elapsed >= timeout_sec / 2 && retry_count % 10 == 0 && getenv("FS_LOCK_DEBUG")) {
			fprintf(stderr, "[PID %d] Waiting for write lock... (%ld/%d seconds)\n", 
				getpid(), elapsed, timeout_sec);
			fflush(stderr);
		}
		
		usleep(100000);
	}
}

static void fs_unlock(void) {
	pthread_mutex_lock(&lock_mutex);
	
	if (write_lock_count > 0) {
		write_lock_count--;
		if (write_lock_count == 0 && global_fs_lock_fd != -1) {
			struct flock lock;
			lock.l_type = F_UNLCK;
			lock.l_whence = SEEK_SET;
			lock.l_start = 0;
			lock.l_len = 0;
			fcntl(global_fs_lock_fd, F_SETLK, &lock);
		}
	}
	
	pthread_mutex_unlock(&lock_mutex);
}

uint32_t alloc(uint32_t size, int verbose);
void fs_free(uint32_t start, uint32_t size);
void write_metadata();
void fs_rm(const char *name, int verbose);
FSHandle fs_open(const char *name, int flags, int verbose);
int fs_read(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
int fs_write(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
void fs_shrink(FSHandle *h, uint32_t new_size, int verbose);

FSHandle fs_open_impl(const char *name, int flags, int verbose) { return fs_open(name, flags, verbose); }
int fs_read_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) { return fs_read(h, pos, n, buffer, verbose); }
int fs_write_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) { return fs_write(h, pos, n, buffer, verbose); }
void fs_rm_impl(const char *name, int verbose) { fs_rm(name, verbose); }
void fs_shrink_impl(FSHandle *h, uint32_t new_size, int verbose) { fs_shrink(h, new_size, verbose); }

static inline uint32_t block_to_bitnum(uint32_t block_addr) {
	return (block_addr / BLOCK_SIZE);
}

static inline uint32_t bitnum_to_block(uint32_t bitnum) {
	return bitnum * BLOCK_SIZE;
}

static inline int get_bit(uint32_t bitnum) {
	uint32_t byte_offset = bitnum / 8;
	uint32_t bit_offset = bitnum % 8;
	uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
	
	uint8_t byte;
	fseek(disk, bitmap_offset, SEEK_SET);
	fread(&byte, 1, 1, disk);
	return (byte >> bit_offset) & 1;
}

static inline void set_bit(uint32_t bitnum, int value) {
	uint32_t byte_offset = bitnum / 8;
	uint32_t bit_offset = bitnum % 8;
	uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
	
	uint8_t byte;
	fseek(disk, bitmap_offset, SEEK_SET);
	fread(&byte, 1, 1, disk);
	
	if (value) {
		byte |= (1 << bit_offset);
	} else {
		byte &= ~(1 << bit_offset);
	}
	
	fseek(disk, bitmap_offset, SEEK_SET);
	fwrite(&byte, 1, 1, disk);
	fflush(disk);
}

static inline void mark_block_used(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	set_bit(bitnum, 1);
}

static inline void mark_block_free(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	set_bit(bitnum, 0);
}

static inline int is_block_free(uint32_t block_addr) {
	uint32_t bitnum = block_to_bitnum(block_addr);
	return get_bit(bitnum) == 0;
}


void read_metadata() {
	fs_lock();
	fseek(disk, 0, SEEK_SET);
	fread(&meta, sizeof(Metadata), 1, disk);

	if (meta.magic != MAGIC_NUMBER) {
		printf("No valid filesystem found. Creating new one...\n");
		meta.magic = MAGIC_NUMBER;
		meta.version = 1;
		meta.last_block = sizeof(Metadata);
		meta.data_start = DATA_START_BLOCK * BLOCK_SIZE;
		meta.files_head = 0;
		meta.users_head = 0;
		meta.groups_head = 0;
		meta.next_uid = 1;
		meta.next_gid = 1;
		meta.freelist_head = 0;
		
		uint8_t zero = 0;
		uint32_t bitmap_start = BITMAP_BLOCK * BLOCK_SIZE;
		for (uint32_t i = 0; i < BITMAP_SIZE; i++) {
			fseek(disk, bitmap_start + i, SEEK_SET);
			fwrite(&zero, 1, 1, disk);
		}
		
		mark_block_used(0);
		mark_block_used(BITMAP_BLOCK * BLOCK_SIZE);
		
		fseek(disk, 0, SEEK_SET);
		fwrite(&meta, sizeof(Metadata), 1, disk);
		fflush(disk);
	}
	
	if (meta.users_head == 0 && meta.groups_head == 0) {
		meta.files_head = 0;
		meta.users_head = 0;
		meta.groups_head = 0;
		meta.next_uid = 1;
		meta.next_gid = 1;
		fseek(disk, 0, SEEK_SET);
		fwrite(&meta, sizeof(Metadata), 1, disk);
		fflush(disk);
	}
	fs_unlock();
}

void write_metadata() {
	fs_lock();
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	fs_unlock();
}

int find_user(const char *username, User *out, uint32_t *offset_out) {
	uint32_t ptr = meta.users_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		User u;
		fread(&u, sizeof(User), 1, disk);
		
		if (strcmp(u.username, username) == 0) {
			if (out) *out = u;
			if (offset_out) *offset_out = ptr;
			return 1;
		}
		
		ptr = u.next;
	}
	return 0;
}

int find_user_by_uid(uint32_t uid, User *out) {
	uint32_t ptr = meta.users_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		User u;
		fread(&u, sizeof(User), 1, disk);
		
		if (u.uid == uid) {
			if (out) *out = u;
			return 1;
		}
		
		ptr = u.next;
	}
	return 0;
}

static void ensure_metadata_space(uint32_t entry_size) {
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + entry_size > BLOCK_SIZE) {
		uint32_t next_block = current_block + 1;
		
		if (next_block == BITMAP_BLOCK) {
			next_block = DATA_START_BLOCK;
		}
		
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return;
		}
		meta.last_block = new_meta_block;
	}
}

int find_group(const char *groupname, Group *out, uint32_t *offset_out) {
	uint32_t ptr = meta.groups_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		Group g;
		fread(&g, sizeof(Group), 1, disk);
		
		if (strcmp(g.groupname, groupname) == 0) {
			if (out) *out = g;
			if (offset_out) *offset_out = ptr;
			return 1;
		}
		
		ptr = g.next;
	}
	return 0;
}

int find_group_by_gid(uint32_t gid, Group *out) {
	uint32_t ptr = meta.groups_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		Group g;
		fread(&g, sizeof(Group), 1, disk);
		
		if (g.gid == gid) {
			if (out) *out = g;
			return 1;
		}
		
		ptr = g.next;
	}
	return 0;
}

uint32_t append_user(User *u) {
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(User) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;
	
	if (meta.users_head == 0) {
		meta.users_head = offset;
	} else {
		uint32_t ptr = meta.users_head;
		while (ptr != 0) {
			User current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(User), 1, disk);
			
			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(User), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	u->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(u, sizeof(User), 1, disk);
	
	meta.last_block += sizeof(User);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	return offset;
}

uint32_t append_group(Group *g) {
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(Group) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;
	
	if (meta.groups_head == 0) {
		meta.groups_head = offset;
	} else {
		uint32_t ptr = meta.groups_head;
		while (ptr != 0) {
			Group current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(Group), 1, disk);
			
			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	g->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(g, sizeof(Group), 1, disk);
	
	meta.last_block += sizeof(Group);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	return offset;
}

void initialize_root_user() {
	User root_user;
	if (find_user("root", NULL, NULL)) {
		return;
	}
	
	strncpy(root_user.username, "root", 31);
	strncpy(root_user.password, "root", 31);
	root_user.uid = 0;
	root_user.gid = 0;
	
	append_user(&root_user);
	
	Group root_group;
	if (!find_group("root", NULL, NULL)) {
		strncpy(root_group.groupname, "root", 31);
		root_group.gid = 0;
		root_group.member_count = 1;
		root_group.members[0] = 0;
		append_group(&root_group);
	}
}

int user_in_group(uint32_t uid, uint32_t gid) {
	if (uid == 0) return 1;
	
	Group g;
	if (!find_group_by_gid(gid, &g)) {
		return 0;
	}
	
	for (uint32_t i = 0; i < g.member_count; i++) {
		if (g.members[i] == uid) {
			return 1;
		}
	}
	
	User u;
	if (find_user_by_uid(uid, &u) && u.gid == gid) {
		return 1;
	}
	
	return 0;
}

int authenticate_user(const char *username, const char *password) {
	User u;
	if (!find_user(username, &u, NULL)) {
		return -1;
	}
	
	if (strcmp(u.password, password) == 0) {
		return u.uid;
	}
	return -1;
}

int login_user(const char *username, const char *password) {
	fs_lock();
	int uid = authenticate_user(username, password);
	if (uid >= 0) {
		session.current_uid = uid;
		strncpy(session.current_username, username, 31);
		session.logged_in = 1;
		fs_unlock();
		return 1;
	}
	fs_unlock();
	return 0;
}

int su_user(const char *username) {
	if (session.current_uid == 0) {
		User u;
		if (find_user(username, &u, NULL)) {
			session.current_uid = u.uid;
			strncpy(session.current_username, username, 31);
			return 1;
		}
		return 0;
	}
	
	char password[32];
	printf("Password: ");
	fgets(password, 32, stdin);
	password[strcspn(password, "\n")] = 0;
	
	return login_user(username, password);
}

uint32_t get_current_uid() {
	return session.current_uid;
}

int is_root() {
	return session.current_uid == 0;
}

int check_permission(FileEntry *entry, char operation) {
	if (is_root()) {
		return 1;
	}
	
	uint32_t uid = get_current_uid();
	uint32_t perm = entry->permission;
	
	int bit_offset;
	
	if (entry->owner_uid == uid) {
		bit_offset = 6;
	} else if (user_in_group(uid, entry->owner_gid)) {
		bit_offset = 3;
	} else {
		bit_offset = 0;
	}
	
	int perm_bit = 0;
	switch (operation) {
		case 'r':
			perm_bit = bit_offset + 2;
			break;
		case 'w':
			perm_bit = bit_offset + 1;
			break;
		case 'x':
			perm_bit = bit_offset;
			break;
		default:
			return 0;
	}
	
	return (perm >> perm_bit) & 1;
}

uint32_t parse_permissions(const char *mode) {
	uint32_t perm = 0;
    
	if (strlen(mode) != 9) {
		return 0;
	}
	
	if (mode[0] == 'r') perm |= (1 << 8);
	if (mode[1] == 'w') perm |= (1 << 7);
	if (mode[2] == 'x') perm |= (1 << 6);
	
	if (mode[3] == 'r') perm |= (1 << 5);
	if (mode[4] == 'w') perm |= (1 << 4);
	if (mode[5] == 'x') perm |= (1 << 3);
	
	if (mode[6] == 'r') perm |= (1 << 2);
	if (mode[7] == 'w') perm |= (1 << 1);
	if (mode[8] == 'x') perm |= (1 << 0);
	
	return perm;
}

void format_permissions(uint32_t perm, char *output) {
	output[0] = (perm & (1 << 8)) ? 'r' : '-';
	output[1] = (perm & (1 << 7)) ? 'w' : '-';
	output[2] = (perm & (1 << 6)) ? 'x' : '-';
	output[3] = (perm & (1 << 5)) ? 'r' : '-';
	output[4] = (perm & (1 << 4)) ? 'w' : '-';
	output[5] = (perm & (1 << 3)) ? 'x' : '-';
	output[6] = (perm & (1 << 2)) ? 'r' : '-';
	output[7] = (perm & (1 << 1)) ? 'w' : '-';
	output[8] = (perm & (1 << 0)) ? 'x' : '-';
	output[9] = '\0';
}

int find_file(const char *name, FileEntry *out, uint32_t *offset_out) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("find_file");
	
	uint32_t ptr = meta.files_head;
	
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		fread(&e, sizeof(FileEntry), 1, disk);

		if (strcmp(e.name, name) == 0) {
			if (out) *out = e;
			if (offset_out) *offset_out = ptr;
			PROFILE_FUNC_STOP("find_file");
			PROFILE_FUNC_END();
			return 1;
		}

		ptr = e.next;
	}
	PROFILE_FUNC_STOP("find_file");
	PROFILE_FUNC_END();
	return 0;
}

uint32_t append_file_entry(FileEntry *e) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("append_file_entry");
	
	uint32_t current_block = meta.last_block / BLOCK_SIZE;
	uint32_t offset_in_block = meta.last_block % BLOCK_SIZE;
	
	if (offset_in_block + sizeof(FileEntry) > BLOCK_SIZE) {
		uint32_t new_meta_block = alloc(BLOCK_SIZE, 0);
		if (new_meta_block == 0) {
			printf("Error: Out of space for metadata\n");
			return 0;
		}
		meta.last_block = new_meta_block;
	}
	
	uint32_t offset = meta.last_block;

	if (meta.files_head == 0) {
		meta.files_head = offset;
	} else {
		PROFILE_ZONE_N(list_traversal);
		uint32_t ptr = meta.files_head;
		while (ptr != 0) {
			FileEntry current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(FileEntry), 1, disk);

			if (current.next == 0) {
				current.next = offset;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(FileEntry), 1, disk);
				fflush(disk);
				break;
			}

			ptr = current.next;
		}
		PROFILE_ZONE_END_N(list_traversal);
	}

	e->next = 0;
	fseek(disk, offset, SEEK_SET);
	fwrite(e, sizeof(FileEntry), 1, disk);

	meta.last_block += sizeof(FileEntry);
	
	fseek(disk, 0, SEEK_SET);
	fwrite(&meta, sizeof(Metadata), 1, disk);
	fflush(disk);
	
	PROFILE_FUNC_STOP("append_file_entry");
	PROFILE_FUNC_END();
	return offset;
}

FSHandle fs_open(const char *name, int flags, int verbose) {
	PROFILE_FUNC_START("fs_open");
	// Use write lock since we may modify filesystem (create file)
	if (fs_lock() != 0) {
		FSHandle h = {0};
		if (verbose) printf("Error: Failed to acquire lock.\n");
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}
	
	FSHandle h;
	h.open = 0;

	if (!session.logged_in) {
		if (verbose) printf("Permission denied: Not logged in.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	FileEntry e;
	uint32_t offset;

	if (find_file(name, &e, &offset)) {
		if (!check_permission(&e, 'r')) {
			if (verbose) printf("Permission denied: No read permission for file '%s'.\n", name);
			fs_unlock();
			PROFILE_FUNC_STOP("fs_open");
			return h;
		}
		
		if ((flags & WRITE) && !check_permission(&e, 'w')) {
			if (verbose) printf("Permission denied: No write permission for file '%s'.\n", name);
			fs_unlock();
			PROFILE_FUNC_STOP("fs_open");
			return h;
		}
		
		h.entry = e;
		h.can_write = (flags & WRITE);
		h.offset_in_fs = offset;
		h.open = 1;
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	if (!(flags & CREATE)) {
		if (verbose) printf("File not found and CREATE flag not passed.\n");
		fs_unlock();
		PROFILE_FUNC_STOP("fs_open");
		return h;
	}

	FileEntry newf = {0};
	strncpy(newf.name, name, 31);
	newf.size = 0;
	newf.start = alloc(BLOCK_SIZE, 0);
	newf.next = 0;
	newf.owner_uid = get_current_uid();
	newf.owner_gid = 0;
	newf.permission = parse_permissions("rw-rw-r--");

	User u;
	if (find_user_by_uid(get_current_uid(), &u)) {
		newf.owner_gid = u.gid;
	}

	uint32_t new_offset = append_file_entry(&newf);

	h.entry = newf;
	h.can_write = (flags & WRITE);
	h.offset_in_fs = new_offset;
	h.open = 1;
	fs_unlock();
	PROFILE_FUNC_STOP("fs_open");
	return h;
}

void update_file_entry(FSHandle *h) {
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fwrite(&h->entry, sizeof(FileEntry), 1, disk);
	fflush(disk);
}

int fs_read(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) {
	PROFILE_FUNC_START("fs_read");
	if (!h->open) { PROFILE_FUNC_STOP("fs_read"); return -1; }
	
	// Use read lock instead of write lock for read operations
	if (fs_lock_read() != 0) {
		if (verbose) printf("Error: Failed to acquire read lock.\n");
		PROFILE_FUNC_STOP("fs_read");
		return -1;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'r')) {
		fs_unlock_read();
		if (verbose) printf("Permission denied: No read permission.\n");
		PROFILE_FUNC_STOP("fs_read");
		return -1;
	}
	
	if (pos >= h->entry.size) {
		fs_unlock_read();
		PROFILE_FUNC_STOP("fs_read");
		return 0;
	}

	uint32_t can_read = h->entry.size - pos;
	if (n > can_read) n = can_read;

	fseek(disk, h->entry.start + pos, SEEK_SET);
	fread(buffer, 1, n, disk);
	
	fs_unlock_read();
	PROFILE_FUNC_STOP("fs_read");
	return n;
}

int fs_write(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose) {
	PROFILE_FUNC_START("fs_write");
	if (!h->open || !h->can_write) { PROFILE_FUNC_STOP("fs_write"); return -1; }
	
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire write lock.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'w')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No write permission.\n");
		PROFILE_FUNC_STOP("fs_write");
		return -1;
	}

	uint32_t end_pos = pos + n;

	if (h->entry.start < DATA_START_BLOCK * BLOCK_SIZE) {
		fs_unlock();
		if (verbose) printf("Error: File data overlaps with metadata/bitmap (start=%u). File may be corrupted.\n", h->entry.start);
		return -1;
	}

	if (end_pos > h->entry.size) {
		uint32_t old_blocks = (h->entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		if (h->entry.size == 0) old_blocks = 1;
		uint32_t new_blocks = (end_pos + BLOCK_SIZE - 1) / BLOCK_SIZE;
		
		if (new_blocks > old_blocks) {
			uint32_t blocks_needed = new_blocks - old_blocks;
			uint32_t expansion_start_block = block_to_bitnum(h->entry.start) + old_blocks;
			
			int can_expand_in_place = 1;
			for (uint32_t i = 0; i < blocks_needed; i++) {
				if (!is_block_free(bitnum_to_block(expansion_start_block + i))) {
					can_expand_in_place = 0;
					break;
				}
			}
			
			if (can_expand_in_place) {
				for (uint32_t i = 0; i < blocks_needed; i++) {
					mark_block_used(bitnum_to_block(expansion_start_block + i));
				}
				fflush(disk);
			} else {
				uint32_t old_start = h->entry.start;
				uint32_t old_size = h->entry.size > 0 ? h->entry.size : BLOCK_SIZE;
				uint32_t new_start = alloc(end_pos, 0);
				
				if (new_start == 0) {
					fs_unlock();
					if (verbose) printf("Error: Failed to allocate space\n");
					return -1;
				}
				
				if (h->entry.size > 0) {
					uint8_t *temp_buffer = malloc(h->entry.size);
					fseek(disk, old_start, SEEK_SET);
					fread(temp_buffer, 1, h->entry.size, disk);
					fseek(disk, new_start, SEEK_SET);
					fwrite(temp_buffer, 1, h->entry.size, disk);
					free(temp_buffer);
				}
				
				fs_free(old_start, old_size);
				h->entry.start = new_start;
			}
		}
		
		h->entry.size = end_pos;
		update_file_entry(h);
	}

	fseek(disk, h->entry.start + pos, SEEK_SET);
	
	fwrite(buffer, 1, n, disk);
	fflush(disk);
	
	fs_unlock();
	PROFILE_FUNC_STOP("fs_write");
	return n;
}

void fs_shrink(FSHandle *h, uint32_t new_size, int verbose) {
	if (!h->open || !h->can_write) return;
	
	// FIXED: Acquire lock before modifying file (was missing!)
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock for shrink operation.\n");
		return;
	}
	
	fseek(disk, h->offset_in_fs, SEEK_SET);
	fread(&h->entry, sizeof(FileEntry), 1, disk);
	
	if (!check_permission(&h->entry, 'w')) {
		fs_unlock();
		if (verbose) printf("Permission denied: No write permission.\n");
		return;
	}

	if (new_size < h->entry.size) {
		uint32_t old_blocks = (h->entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		uint32_t new_blocks = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
		if (new_size == 0) new_blocks = 1;
		
		if (new_blocks < old_blocks) {
			uint32_t freed_start = h->entry.start + (new_blocks * BLOCK_SIZE);
			uint32_t freed_size = (old_blocks - new_blocks) * BLOCK_SIZE;
			fs_free(freed_start, freed_size);
		}
		
		h->entry.size = new_size;
		update_file_entry(h);
	}
	
	fs_unlock();
}

void fs_rm(const char *name, int verbose) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("fs_rm");
	
	if (fs_lock() != 0) {
		if (verbose) printf("Error: Failed to acquire lock for delete operation.\n");
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	
	if (!session.logged_in) {
		fs_unlock();
		if (verbose) printf("Permission denied: Not logged in.\n");
		PROFILE_FUNC_STOP("fs_rm");
		PROFILE_FUNC_END();
		return;
	}
	
	uint32_t ptr = meta.files_head;
	uint32_t prev = 0;

	PROFILE_ZONE_N(find_and_unlink);
	while (ptr != 0) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		fread(&e, sizeof(FileEntry), 1, disk);

		if (strcmp(e.name, name) == 0) {
			PROFILE_ZONE_END_N(find_and_unlink);
			
			int can_delete = is_root() || (e.owner_uid == get_current_uid());
			
			if (!can_delete) {
				fs_unlock();
				if (verbose) printf("Permission denied: You are not the owner of file '%s'.\n", name);
				PROFILE_FUNC_STOP("fs_rm");
				PROFILE_FUNC_END();
				return;
			}
			
			if (prev == 0) {
				meta.files_head = e.next;
			} else {
				FileEntry prevE;
				fseek(disk, prev, SEEK_SET);
				fread(&prevE, sizeof(FileEntry), 1, disk);
				prevE.next = e.next;
				fseek(disk, prev, SEEK_SET);
				fwrite(&prevE, sizeof(FileEntry), 1, disk);
				fflush(disk);
			}
			
			fseek(disk, 0, SEEK_SET);
			fwrite(&meta, sizeof(Metadata), 1, disk);
			fflush(disk);
			
			uint32_t size = e.size > 0 ? e.size : BLOCK_SIZE;
			fs_free(e.start, size);
			
			fs_unlock();
			if (verbose) printf("Deleted file '%s' and freed %u bytes\n", name, size);
			PROFILE_FUNC_STOP("fs_rm");
			PROFILE_FUNC_END();
			return;
		}

		prev = ptr;
		ptr = e.next;
	}
	PROFILE_ZONE_END_N(find_and_unlink);
	
	fs_unlock();
	if (verbose) printf("File '%s' not found.\n", name);
	PROFILE_FUNC_STOP("fs_rm");
	PROFILE_FUNC_END();
}

void fs_close(FSHandle *h) {
	h->open = 0;
}

uint32_t alloc(uint32_t size, int verbose) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("alloc");
	
	if (size == 0) { PROFILE_FUNC_STOP("alloc"); PROFILE_FUNC_END(); return 0; }
	
	uint32_t blocks_needed = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	
	uint32_t start_bit = DATA_START_BLOCK;
	uint32_t consecutive_free = 0;
	uint32_t found_start_bit = 0;
	
	PROFILE_ZONE_N(bitmap_scan);
	for (uint32_t bitnum = start_bit; bitnum < TOTAL_BLOCKS; bitnum++) {
		uint32_t byte_offset = bitnum / 8;
		uint32_t bit_offset = bitnum % 8;
		uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
		
		uint8_t byte;
		fseek(disk, bitmap_offset, SEEK_SET);
		fread(&byte, 1, 1, disk);
		int is_free = ((byte >> bit_offset) & 1) == 0;
		
		if (is_free) {
			if (consecutive_free == 0) {
				found_start_bit = bitnum;
			}
			consecutive_free++;
			
			if (consecutive_free >= blocks_needed) {
				PROFILE_ZONE_END_N(bitmap_scan);
				
				uint32_t allocated_start = bitnum_to_block(found_start_bit);
				
				PROFILE_ZONE_N(mark_blocks);
				for (uint32_t i = 0; i < blocks_needed; i++) {
					uint32_t mark_bitnum = found_start_bit + i;
					uint32_t mark_byte_offset = mark_bitnum / 8;
					uint32_t mark_bit_offset = mark_bitnum % 8;
					uint32_t mark_bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + mark_byte_offset;
					
					uint8_t mark_byte;
					fseek(disk, mark_bitmap_offset, SEEK_SET);
					fread(&mark_byte, 1, 1, disk);
					mark_byte |= (1 << mark_bit_offset);
					fseek(disk, mark_bitmap_offset, SEEK_SET);
					fwrite(&mark_byte, 1, 1, disk);
				}
				PROFILE_ZONE_END_N(mark_blocks);
				
				fflush(disk);
				PROFILE_FUNC_STOP("alloc");
				PROFILE_FUNC_END();
				return allocated_start;
			}
		} else {
			consecutive_free = 0;
		}
	}
	PROFILE_ZONE_END_N(bitmap_scan);
	
	if (verbose) printf("Error: Out of space\n");
	PROFILE_FUNC_STOP("alloc");
	PROFILE_FUNC_END();
	return 0;
}

void fs_free(uint32_t start, uint32_t size) {
	PROFILE_FUNC();
	PROFILE_FUNC_START("fs_free");
	
	if (size == 0) { PROFILE_FUNC_STOP("fs_free"); PROFILE_FUNC_END(); return; }
	
	uint32_t blocks_used = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	uint32_t start_bitnum = block_to_bitnum(start);
	
	for (uint32_t i = 0; i < blocks_used; i++) {
		uint32_t bitnum = start_bitnum + i;
		uint32_t byte_offset = bitnum / 8;
		uint32_t bit_offset = bitnum % 8;
		uint32_t bitmap_offset = BITMAP_BLOCK * BLOCK_SIZE + byte_offset;
		
		uint8_t byte;
		fseek(disk, bitmap_offset, SEEK_SET);
		fread(&byte, 1, 1, disk);
		byte &= ~(1 << bit_offset);
		fseek(disk, bitmap_offset, SEEK_SET);
		fwrite(&byte, 1, 1, disk);
	}
	
	fflush(disk);
	PROFILE_FUNC_STOP("fs_free");
	PROFILE_FUNC_END();
}

void freelist_add(uint32_t first, uint32_t last) {
	FreeBlock fb;
	fb.first_block = first;
	fb.last_block = last;
	fb.next = 0;
	
	uint32_t offset = meta.last_block;
	fseek(disk, offset, SEEK_SET);
	fwrite(&fb, sizeof(FreeBlock), 1, disk);
	
	fb.next = meta.freelist_head;
	meta.freelist_head = offset;
	meta.last_block += sizeof(FreeBlock);
	write_metadata();
}

void freelist_remove(uint32_t offset) {
	if (meta.freelist_head == offset) {
		FreeBlock fb;
		fseek(disk, offset, SEEK_SET);
		fread(&fb, sizeof(FreeBlock), 1, disk);
		meta.freelist_head = fb.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.freelist_head;
		while (ptr != 0) {
			FreeBlock fb;
			fseek(disk, ptr, SEEK_SET);
			fread(&fb, sizeof(FreeBlock), 1, disk);
			
			if (fb.next == offset) {
				FreeBlock to_remove;
				fseek(disk, offset, SEEK_SET);
				fread(&to_remove, sizeof(FreeBlock), 1, disk);
				
				fb.next = to_remove.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&fb, sizeof(FreeBlock), 1, disk);
				break;
			}
			
			ptr = fb.next;
		}
	}
}

void freelist_print() {
	printf("Bitmask Freelist Statistics:\n");
	
	uint32_t total_blocks = TOTAL_BLOCKS;
	uint32_t free_blocks = 0;
	uint32_t used_blocks = 0;
	uint32_t free_ranges = 0;
	uint32_t in_range = 0;
	
	for (uint32_t bitnum = 0; bitnum < total_blocks; bitnum++) {
		if (is_block_free(bitnum_to_block(bitnum))) {
			free_blocks++;
			if (!in_range) {
				free_ranges++;
				in_range = 1;
			}
		} else {
			used_blocks++;
			in_range = 0;
		}
	}
	
	printf("  Total blocks: %u\n", total_blocks);
	printf("  Free blocks: %u (%.2f%%)\n", free_blocks, (free_blocks * 100.0) / total_blocks);
	printf("  Used blocks: %u (%.2f%%)\n", used_blocks, (used_blocks * 100.0) / total_blocks);
	printf("  Free block ranges: %u\n", free_ranges);
	printf("  Block size: %u bytes\n", BLOCK_SIZE);
	printf("  Bitmap location: Block %u\n", BITMAP_BLOCK);
	printf("  Data starts at: Block %u\n", DATA_START_BLOCK);
}

void fs_stats() {
	uint32_t metadata_used = meta.last_block;
	
	uint32_t data_used = 0;
	int count = 0;
	uint32_t ptr = meta.files_head;

	while (ptr != 0 && ptr < FS_SIZE) {
		fseek(disk, ptr, SEEK_SET);
		FileEntry e;
		size_t read_count = fread(&e, sizeof(FileEntry), 1, disk);
		
		if (read_count != 1) break;
		
		data_used += e.size;
		count++;
		ptr = e.next;
	}

	uint32_t used_memory = metadata_used + data_used;
	uint32_t free_memory = FS_SIZE - used_memory;

	printf("FS Stats:\n");
	printf("  Total Size : %d bytes\n", FS_SIZE);
	printf("  Used       : %u bytes (Metadata: %u, Data: %u)\n", used_memory, metadata_used, data_used);
	printf("  Free       : %u bytes\n", free_memory);
	printf("  Files      : %d\n", count);
}

void get_file_stat() {
	if (!current_handle.open) {
		printf("No file is currently open.\n");
		return;
	}

	FileEntry *e = &current_handle.entry;
	printf("File: %s\n", e->name);
	printf("  Size: %u bytes\n", e->size);
	printf("  Start: %u\n", e->start);
}

void cmd_chmod(const char *path, const char *mode) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	if (!is_root() && e.owner_uid != get_current_uid()) {
		printf("Permission denied: You are not the owner of file '%s'.\n", path);
		return;
	}
	
	uint32_t perm = parse_permissions(mode);
	if (perm == 0) {
		printf("Invalid permission format. Use format like 'rwxrwxrwx' or 'rw-r--r--'.\n");
		return;
	}
	
	e.permission = perm;
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed permissions of '%s' to %s\n", path, mode);
}

void cmd_chown(const char *path, const char *user_group) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can change file ownership.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	char user_part[32] = {0};
	char group_part[32] = {0};
	
	char *colon = strchr(user_group, ':');
	if (colon) {
		strncpy(user_part, user_group, colon - user_group);
		strncpy(group_part, colon + 1, 31);
	} else {
		strncpy(user_part, user_group, 31);
	}
	
	if (user_part[0] != '\0') {
		User u;
		if (!find_user(user_part, &u, NULL)) {
			printf("User '%s' not found.\n", user_part);
			return;
		}
		e.owner_uid = u.uid;
		e.owner_gid = u.gid;
	}
	
	if (group_part[0] != '\0') {
		Group g;
		if (!find_group(group_part, &g, NULL)) {
			printf("Group '%s' not found.\n", group_part);
			return;
		}
		e.owner_gid = g.gid;
	}
	
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed ownership of '%s'\n", path);
}

void cmd_chgrp(const char *path, const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	uint32_t offset;
	if (!find_file(path, &e, &offset)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	if (!is_root() && e.owner_uid != get_current_uid()) {
		Group g;
		if (!find_group(groupname, &g, NULL)) {
			printf("Group '%s' not found.\n", groupname);
			return;
		}
		if (!user_in_group(get_current_uid(), g.gid)) {
			printf("Permission denied: You must be the owner or root, or be a member of the target group.\n");
			return;
		}
	}
	
	Group g;
	if (!find_group(groupname, &g, NULL)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
	e.owner_gid = g.gid;
	fseek(disk, offset, SEEK_SET);
	fwrite(&e, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	printf("Changed group of '%s' to '%s'\n", path, groupname);
}

void cmd_getfacl(const char *path) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	FileEntry e;
	if (!find_file(path, &e, NULL)) {
		printf("File '%s' not found.\n", path);
		return;
	}
	
	User owner;
	Group group;
	char owner_name[32] = "unknown";
	char group_name[32] = "unknown";
	
	if (find_user_by_uid(e.owner_uid, &owner)) {
		strncpy(owner_name, owner.username, 31);
	}
	if (find_group_by_gid(e.owner_gid, &group)) {
		strncpy(group_name, group.groupname, 31);
	}
	
	char perm_str[10];
	format_permissions(e.permission, perm_str);
	
	printf("File: %s\n", path);
	printf("  Owner: %s (uid: %u)\n", owner_name, e.owner_uid);
	printf("  Group: %s (gid: %u)\n", group_name, e.owner_gid);
	printf("  Permissions: %s\n", perm_str);
}

void cmd_useradd(const char *username) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can add users.\n");
		return;
	}
	
	if (find_user(username, NULL, NULL)) {
		printf("User '%s' already exists.\n", username);
		return;
	}
	
	User new_user = {0};
	strncpy(new_user.username, username, 31);
	strncpy(new_user.password, username, 31);
	new_user.uid = meta.next_uid++;
	new_user.gid = 0;
	
	append_user(&new_user);
	printf("User '%s' added with uid %u\n", username, new_user.uid);
}

void cmd_userdel(const char *username) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can delete users.\n");
		return;
	}
	
	if (strcmp(username, "root") == 0) {
		printf("Cannot delete root user.\n");
		return;
	}
	
	User u;
	uint32_t offset;
	if (!find_user(username, &u, &offset)) {
		printf("User '%s' not found.\n", username);
		return;
	}
	
	uint32_t ptr = meta.files_head;
	int has_files = 0;
	while (ptr != 0) {
		FileEntry e;
		fseek(disk, ptr, SEEK_SET);
		fread(&e, sizeof(FileEntry), 1, disk);
		
		if (e.owner_uid == u.uid) {
			has_files = 1;
			break;
		}
		
		ptr = e.next;
	}
	
	if (has_files) {
		printf("Cannot delete user '%s': user owns files.\n", username);
		return;
	}
	
	uint32_t gptr = meta.groups_head;
	while (gptr != 0) {
		Group g;
		fseek(disk, gptr, SEEK_SET);
		fread(&g, sizeof(Group), 1, disk);
		
		for (uint32_t i = 0; i < g.member_count; i++) {
			if (g.members[i] == u.uid) {
				for (uint32_t j = i; j < g.member_count - 1; j++) {
					g.members[j] = g.members[j + 1];
				}
				g.member_count--;
				fseek(disk, gptr, SEEK_SET);
				fwrite(&g, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
		}
		
		gptr = g.next;
	}
	
	if (meta.users_head == offset) {
		meta.users_head = u.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.users_head;
		while (ptr != 0) {
			User current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(User), 1, disk);
			
			if (current.next == offset) {
				current.next = u.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(User), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	printf("User '%s' deleted.\n", username);
}

void cmd_groupadd(const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can add groups.\n");
		return;
	}
	
	if (find_group(groupname, NULL, NULL)) {
		printf("Group '%s' already exists.\n", groupname);
		return;
	}
	
	Group new_group = {0};
	strncpy(new_group.groupname, groupname, 31);
	new_group.gid = meta.next_gid++;
	new_group.member_count = 0;
	
	append_group(&new_group);
	printf("Group '%s' added with gid %u\n", groupname, new_group.gid);
}

void cmd_groupdel(const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can delete groups.\n");
		return;
	}
	
	if (strcmp(groupname, "root") == 0) {
		printf("Cannot delete root group.\n");
		return;
	}
	
	Group g;
	uint32_t offset;
	if (!find_group(groupname, &g, &offset)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
	if (meta.groups_head == offset) {
		meta.groups_head = g.next;
		write_metadata();
	} else {
		uint32_t ptr = meta.groups_head;
		while (ptr != 0) {
			Group current;
			fseek(disk, ptr, SEEK_SET);
			fread(&current, sizeof(Group), 1, disk);
			
			if (current.next == offset) {
				current.next = g.next;
				fseek(disk, ptr, SEEK_SET);
				fwrite(&current, sizeof(Group), 1, disk);
				fflush(disk);
				break;
			}
			
			ptr = current.next;
		}
	}
	
	printf("Group '%s' deleted.\n", groupname);
}

void cmd_usermod(const char *username, const char *groupname) {
	if (!session.logged_in) {
		printf("Permission denied: Not logged in.\n");
		return;
	}
	
	if (!is_root()) {
		printf("Permission denied: Only root can modify users.\n");
		return;
	}
	
	User u;
	uint32_t u_offset;
	if (!find_user(username, &u, &u_offset)) {
		printf("User '%s' not found.\n", username);
		return;
	}
	
	Group g;
	if (!find_group(groupname, &g, NULL)) {
		printf("Group '%s' not found.\n", groupname);
		return;
	}
	
	if (user_in_group(u.uid, g.gid)) {
		printf("User '%s' is already in group '%s'.\n", username, groupname);
		return;
	}
	
	if (g.member_count >= MAX_GROUP_MEMBERS) {
		printf("Group '%s' is full.\n", groupname);
		return;
	}
	
	uint32_t g_offset;
	find_group(groupname, &g, &g_offset);
	
	g.members[g.member_count++] = u.uid;
	fseek(disk, g_offset, SEEK_SET);
	fwrite(&g, sizeof(Group), 1, disk);
	fflush(disk);
	
	printf("Added user '%s' to group '%s'\n", username, groupname);
}

void cmd_stressTest() {
	printf("Starting stress test...\n");
	clock_t start_time = clock();
	
	if (disk) {
		fclose(disk);
		disk = NULL;
	}
	
	unlink(FS_FILENAME);
	
	disk = fopen(FS_FILENAME, "w+b");
	if (!disk) {
		printf("Error: Failed to create filesystem for stress test\n");
		return;
	}
	ftruncate(fileno(disk), FS_SIZE);
	
	read_metadata();
	initialize_root_user();
	
	if (!login_user("root", "root")) {
		printf("Error: Failed to login as root\n");
		fclose(disk);
		return;
	}
	
	printf("Creating %d files...\n", STRESS_TEST_NUM_FILES);
	char filename[64];
	for (int i = 0; i < STRESS_TEST_NUM_FILES; i++) {
		snprintf(filename, sizeof(filename), "stress_file_%d.txt", i);
		FSHandle f = fs_open(filename, CREATE | WRITE, 0);
		if (!f.open) {
			continue;
		}
		char data[32];
		snprintf(data, sizeof(data), "Data for file %d", i);
		fs_write(&f, 0, strlen(data), (uint8_t*)data, 0);
		fs_close(&f);
	}
	
	printf("Performing %d random operations...\n", STRESS_TEST_NUM_OPERATIONS);
	srand(time(NULL));
	
	for (int op = 0; op < STRESS_TEST_NUM_OPERATIONS; op++) {
		int operation = rand() % 4;
		
		switch (operation) {
			case 0: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				FSHandle f = fs_open(filename, 0, 0);
				if (f.open) {
					uint8_t buffer[64];
					fs_read(&f, 0, 32, buffer, 0);
					fs_close(&f);
				}
				break;
			}
			case 1: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				FSHandle f = fs_open(filename, WRITE, 0);
				if (f.open) {
					char new_data[64];
					snprintf(new_data, sizeof(new_data), "Updated data %d", op % STRESS_TEST_NUM_FILES);
					fs_write(&f, 0, strlen(new_data), (uint8_t*)new_data, 0);
					fs_close(&f);
				}
				break;
			}
			case 2: {
				snprintf(filename, sizeof(filename), "stress_new_%d.txt", op % STRESS_TEST_NUM_FILES);
				FSHandle f = fs_open(filename, CREATE | WRITE, 0);
				if (f.open) {
					char data[32];
					snprintf(data, sizeof(data), "New file %d", op);
					fs_write(&f, 0, strlen(data), (uint8_t*)data, 0);
					fs_close(&f);
				}
				break;
			}
			case 3: {
				int file_idx = rand() % STRESS_TEST_NUM_FILES;
				snprintf(filename, sizeof(filename), "stress_file_%d.txt", file_idx);
				fs_rm(filename, 0);
				break;
			}
		}
	}
	
	clock_t end_time = clock();
	double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
	
	printf("Stress test completed in %.2f seconds\n", elapsed);
	printf("Operations: %d file creations + %d random operations\n", STRESS_TEST_NUM_FILES, STRESS_TEST_NUM_OPERATIONS);
}

#ifndef EXCLUDE_MAIN
int main() {
	disk = fopen(FS_FILENAME, "r+b");
	if (!disk) {
		disk = fopen(FS_FILENAME, "w+b");
		ftruncate(fileno(disk), FS_SIZE);
	}

	read_metadata();
	initialize_root_user();

	printf("File System Ready.\n");
	printf("Please login.\n");
	
	while (!session.logged_in) {
		char username[32];
		char password[32];
		
		printf("Username: ");
		if (!fgets(username, 32, stdin)) break;
		username[strcspn(username, "\n")] = 0;
		
		if (strlen(username) == 0) continue;
		
		printf("Password: ");
		if (!fgets(password, 32, stdin)) break;
		password[strcspn(password, "\n")] = 0;
		
		if (login_user(username, password)) {
			printf("Logged in as %s\n", username);
		} else {
			printf("Login failed. Please try again.\n");
		}
	}

	while(1){
		char* command = malloc(256);
		printf("%s@filesystem$ ", session.current_username);
		fgets(command, 256, stdin);
		command[strcspn(command, "\n")] = 0;
		
		if(strncmp(command, "get_fs_stats", 12) == 0){
			fs_stats();
		} else if(strncmp(command, "rm ", 3) == 0){
			char filename[32];
			sscanf(command + 3, "%31s", filename);
			fs_rm(filename, 1);
		} else if (strncmp(command, "login ", 6) == 0) {
			char username[32];
			sscanf(command + 6, "%31s", username);
			char password[32];
			printf("Password: ");
			if (fgets(password, 32, stdin)) {
				password[strcspn(password, "\n")] = 0;
				if (login_user(username, password)) {
					printf("Logged in as %s\n", username);
				} else {
					printf("Login failed.\n");
				}
			}
		} else if (strncmp(command, "su ", 3) == 0) {
			char username[32];
			sscanf(command + 3, "%31s", username);
			if (su_user(username)) {
				printf("Switched to user %s\n", username);
			} else {
				printf("Failed to switch user.\n");
			}
		} else if (strncmp(command, "whoami", 6) == 0) {
			printf("%s (uid: %u)\n", session.current_username, session.current_uid);
		} else if (strncmp(command, "logout", 6) == 0) {
			session.logged_in = 0;
			printf("Logged out.\n");
			while (!session.logged_in) {
				char username[32];
				char password[32];
				
				printf("Username: ");
				if (!fgets(username, 32, stdin)) break;
				username[strcspn(username, "\n")] = 0;
				
				if (strlen(username) == 0) continue;
				
				printf("Password: ");
				if (!fgets(password, 32, stdin)) break;
				password[strcspn(password, "\n")] = 0;
				
				if (login_user(username, password)) {
					printf("Logged in as %s\n", username);
				} else {
					printf("Login failed. Please try again.\n");
				}
			}
		} else if (strncmp(command, "useradd ", 8) == 0) {
			char username[32];
			sscanf(command + 8, "%31s", username);
			cmd_useradd(username);
		} else if (strncmp(command, "userdel ", 8) == 0) {
			char username[32];
			sscanf(command + 8, "%31s", username);
			cmd_userdel(username);
		} else if (strncmp(command, "groupadd ", 9) == 0) {
			char groupname[32];
			sscanf(command + 9, "%31s", groupname);
			cmd_groupadd(groupname);
		} else if (strncmp(command, "groupdel ", 9) == 0) {
			char groupname[32];
			sscanf(command + 9, "%31s", groupname);
			cmd_groupdel(groupname);
		} else if (strncmp(command, "usermod ", 8) == 0) {
			char username[32], groupname[32];
			if (sscanf(command + 8, "%31s -aG %31s", username, groupname) == 2) {
				cmd_usermod(username, groupname);
			} else {
				printf("Usage: usermod <user> -aG <group>\n");
			}
		} else if (strncmp(command, "chmod ", 6) == 0) {
			char path[32], mode[10];
			if (sscanf(command + 6, "%31s %9s", path, mode) == 2) {
				cmd_chmod(path, mode);
			} else {
				printf("Usage: chmod <path> <mode>\n");
			}
		} else if (strncmp(command, "chown ", 6) == 0) {
			char path[32], user_group[64];
			if (sscanf(command + 6, "%31s %63s", path, user_group) == 2) {
				cmd_chown(path, user_group);
			} else {
				printf("Usage: chown <path> <user>:<group> or chown <path> <user>\n");
			}
		} else if (strncmp(command, "chgrp ", 6) == 0) {
			char path[32], groupname[32];
			if (sscanf(command + 6, "%31s %31s", path, groupname) == 2) {
				cmd_chgrp(path, groupname);
			} else {
				printf("Usage: chgrp <path> <group>\n");
			}
		} else if (strncmp(command, "getfacl ", 8) == 0) {
			char path[32];
			sscanf(command + 8, "%31s", path);
			cmd_getfacl(path);
		} else if (strncmp(command, "open ", 5) == 0) {
			if (current_handle.open) {
				printf("A file is already open. Please close it first.\n");
				continue;
			}
			char filename[32];
			char mode[8];
			sscanf(command + 5, "%31s %7s", filename, mode);
			int flags = 0;
			if (strchr(mode, 'c')) flags |= CREATE;
			if (strchr(mode, 'w')) flags |= WRITE;
			current_handle = fs_open(filename, flags, 1);
			if (current_handle.open) {
				printf("Opened file '%s' successfully.\n", filename);
			} else {
				printf("Failed to open file '%s'.\n", filename);
			}
		} else if (strncmp(command, "close", 5) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
			} else {
				fs_close(&current_handle);
				printf("Closed the currently open file.\n");
			}
		} else if (strncmp(command, "write ", 6) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}
			if (!current_handle.can_write) {
				printf("File is not opened with write permissions. Use 'w' flag when opening.\n");
				continue;
			}
			uint32_t pos;
			char data[256];
			sscanf(command + 6, "%u %[^\"]", &pos, data);
			int written = fs_write(&current_handle, pos, strlen(data) - 1, (uint8_t *)data, 1);
			if (written > 0) {
				printf("Wrote %d bytes.\n", written);
			} else {
				printf("Failed to write to the file.\n");
			}
		} else if (strncmp(command, "read ", 5) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}

			uint32_t pos, n;
			sscanf(command + 5, "%u %u", &pos, &n);
			uint8_t *buffer = malloc(n + 1);
			int read_bytes = fs_read(&current_handle, pos, n, buffer, 1);
			if (read_bytes > 0) {
				buffer[read_bytes] = '\0';
				for(int i = 0 ; i < read_bytes ; i++)
					if(buffer[i] == '\0') buffer[i] = ' ';
				printf("Read %d bytes: %s\n", read_bytes, buffer);
			} else {
				printf("Failed to read from the file.\n");
			}
			free(buffer);
		} else if (strncmp(command, "shrink ", 7) == 0) {
			if (!current_handle.open) {
				printf("No file is currently open.\n");
				continue;
			}

			uint32_t new_size;
			sscanf(command + 7, "%u", &new_size);
			fs_shrink(&current_handle, new_size, 1);
			printf("Shrunk the file to %u bytes.\n", new_size);
		} else if (strncmp(command, "get_file_stat", 13) == 0) {
			get_file_stat();
		} else if(strncmp(command, "exit", 4) == 0){
			free(command);
			break;
		} else if(strncmp(command, "stressTest", 10) == 0){
			cmd_stressTest();
		} else if(strncmp(command, "viz" , 3) == 0){
			freelist_print();
		} else {
			printf("Unknown command.\n");
		}
		free(command);
	}
	return 0;
}
#endif
