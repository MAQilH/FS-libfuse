#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>

// Structure definitions (must match main.c)
#define MAX_GROUP_MEMBERS 16

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

// Dirent data structure
#define MAX_DIRENT_CHILDREN 128
typedef struct {
	uint32_t child_count;
	uint32_t children[MAX_DIRENT_CHILDREN];
} DirentData;

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

// Global variables are now defined in test.c (see below)

// Forward declarations of functions we'll test
int authenticate_user(const char *username, const char *password);
int login_user(const char *username, const char *password);
int su_user(const char *username);
uint32_t get_current_uid();
int is_root();
int find_user(const char *username, User *out, uint32_t *offset_out);
int find_group(const char *groupname, Group *out, uint32_t *offset_out);
int user_in_group(uint32_t uid, uint32_t gid);
FSHandle fs_open_impl(const char *name, int flags, int verbose);
int fs_read_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
int fs_write_impl(FSHandle *h, uint32_t pos, uint32_t n, uint8_t *buffer, int verbose);
void fs_close(FSHandle *h);
void fs_rm_impl(const char *name, int verbose);

// Wrapper macros for tests - use verbose=0 to suppress output
#define fs_open(name, flags) fs_open_impl(name, flags, 0)
#define fs_read(h, pos, n, buf) fs_read_impl(h, pos, n, buf, 0)
#define fs_write(h, pos, n, buf) fs_write_impl(h, pos, n, buf, 0)
#define fs_rm(name) fs_rm_impl(name, 0)
void cmd_chmod(const char *path, const char *mode);
void cmd_chown(const char *path, const char *user_group);
void cmd_chgrp(const char *path, const char *groupname);
void cmd_getfacl(const char *path);
void cmd_useradd(const char *username);
void cmd_userdel(const char *username);
void cmd_groupadd(const char *groupname);
void cmd_groupdel(const char *groupname);
void cmd_usermod(const char *username, const char *groupname);
int find_file(const char *name, FileEntry *out, uint32_t *offset_out);
void read_metadata();
void initialize_root_user();
void fs_stats();
void fs_shrink_impl(FSHandle *h, uint32_t new_size, int verbose);
#define fs_shrink(h, size) fs_shrink_impl(h, size, 0)

// Dirent and path functions
int fs_cp(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose);
int fs_mv(const char *src_path, const char *dst_path, uint32_t cwd_offset, int verbose);
uint32_t create_dirent(const char *name, uint32_t parent_offset);
int read_dirent(uint32_t dirent_offset, DirentData *out);
int resolve_path(const char *path, uint32_t cwd_offset, uint32_t *out_offset, FileEntry *out_entry, uint32_t *parent_offset);
int is_dirent(FileEntry *e);

// Global variable definitions (must match main.c)
Metadata meta;
FILE *disk = NULL;
FSHandle current_handle = {0};
UserSession session = {0};
uint32_t cwd_offset = 0;

#define FS_FILENAME "test_filesys.db"
#define FS_SIZE (32*1024*4096)
#define TEST_PASSED 0
#define TEST_FAILED 1

#define CREATE 1
#define WRITE 2

#define CONCURRENT_NUM_PROCESSES 4
#define CONCURRENT_NUM_OPERATIONS 20
#define CONCURRENT_RACE_DELAY_US 100

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

void test_result(const char *test_name, int result) {
	tests_run++;
	if (result == TEST_PASSED) {
		tests_passed++;
		printf("[PASS] %s\n", test_name);
	} else {
		tests_failed++;
		printf("[FAIL] %s\n", test_name);
	}
}

// Test 1: Root user initialization
int test_root_user_exists() {
	read_metadata();
	initialize_root_user();
	
	User user_out;
	uint32_t offset;
	int found = find_user("root", &user_out, &offset);
	
	return found ? TEST_PASSED : TEST_FAILED;
}

// Test 2: Authentication with correct password
int test_authentication_correct() {
	if (!login_user("root", "root")) {
		return TEST_FAILED;
	}
	if (get_current_uid() != 0) {
		return TEST_FAILED;
	}
	return TEST_PASSED;
}

// Test 3: Authentication with incorrect password
int test_authentication_incorrect() {
	int uid = authenticate_user("root", "wrongpassword");
	return (uid == -1) ? TEST_PASSED : TEST_FAILED;
}

// Test 4: User creation (requires root)
int test_useradd() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("testuser");
	
	User user_out;
	uint32_t offset;
	int found = find_user("testuser", &user_out, &offset);
	
	return found ? TEST_PASSED : TEST_FAILED;
}

// Test 5: Non-root cannot add users
int test_useradd_permission() {
	// Create a test user first
	if (!is_root()) {
		login_user("root", "root");
	}
	cmd_useradd("testuser2");
	
	// Try to login as non-root and add user
	if (login_user("testuser2", "testuser2")) {
		cmd_useradd("shouldfail");
		// Check if user was created (should not be)
		User user_out;
		uint32_t offset;
		int found = find_user("shouldfail", &user_out, &offset);
		
		// Should not be found
		return found ? TEST_FAILED : TEST_PASSED;
	}
	return TEST_FAILED;
}

// Test 6: Group creation
int test_groupadd() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_groupadd("testgroup");
	
	Group group_out;
	uint32_t offset;
	int found = find_group("testgroup", &group_out, &offset);
	
	return found ? TEST_PASSED : TEST_FAILED;
}

// Test 7: Add user to group
int test_usermod() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("groupuser");
	cmd_groupadd("testgroup2");
	cmd_usermod("groupuser", "testgroup2");
	
	// Get user's uid
	User user_out;
	uint32_t u_offset;
	find_user("groupuser", &user_out, &u_offset);
	uint32_t uid = user_out.uid;
	
	// Get group's gid
	Group group_out;
	uint32_t g_offset;
	find_group("testgroup2", &group_out, &g_offset);
	uint32_t gid = group_out.gid;
	
	// Check if user is in group
	int in_group = user_in_group(uid, gid);
	
	return in_group ? TEST_PASSED : TEST_FAILED;
}

// Test 8: File creation with default permissions
int test_file_creation_permissions() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("test_perms.txt", 1 | 2); // CREATE | WRITE
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Check default permissions (should be rw-rw-r--)
	uint32_t perm = f.entry.permission;
	// rw-rw-r-- = 0110110100 in binary = 0x1B4
	// But we need to check the actual bit pattern
	// Owner read: bit 8, write: bit 7
	// Group read: bit 5, write: bit 4
	// Others read: bit 2
	
	int owner_read = (perm >> 8) & 1;
	int owner_write = (perm >> 7) & 1;
	int group_read = (perm >> 5) & 1;
	int group_write = (perm >> 4) & 1;
	int others_read = (perm >> 2) & 1;
	
	if (owner_read && owner_write && group_read && group_write && others_read) {
		fs_close(&f);
		return TEST_PASSED;
	}
	
	fs_close(&f);
	return TEST_FAILED;
}

// Test 9: File ownership
int test_file_ownership() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("fileowner");
	if (!login_user("fileowner", "fileowner")) {
		return TEST_FAILED;
	}
	
	FSHandle f = fs_open("owned_file.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// File should be owned by fileowner (uid should be > 0)
	if (f.entry.owner_uid == get_current_uid() && f.entry.owner_uid != 0) {
		fs_close(&f);
		return TEST_PASSED;
	}
	
	fs_close(&f);
	return TEST_FAILED;
}

// Test 10: chmod command
int test_chmod() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("chmod_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	cmd_chmod("chmod_test.txt", "rwxrwxrwx");
	
	// Read file entry and check permissions
	FileEntry entry_out;
	uint32_t offset;
	if (!find_file("chmod_test.txt", &entry_out, &offset)) {
		return TEST_FAILED;
	}
	
	uint32_t perm = entry_out.permission;
	
	// Check all bits are set (rwxrwxrwx = 0x1FF)
	if (perm == 0x1FF) {
		return TEST_PASSED;
	}
	
	return TEST_FAILED;
}

// Test 11: chown command
int test_chown() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("newowner");
	cmd_groupadd("newgroup");
	
	FSHandle f = fs_open("chown_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	cmd_chown("chown_test.txt", "newowner:newgroup");
	
	// Check ownership
	FileEntry entry_out;
	uint32_t offset;
	if (!find_file("chown_test.txt", &entry_out, &offset)) {
		return TEST_FAILED;
	}
	
	// Get newowner's uid
	User user_out;
	find_user("newowner", &user_out, &offset);
	uint32_t expected_uid = user_out.uid;
	
	if (entry_out.owner_uid == expected_uid) {
		return TEST_PASSED;
	}
	
	return TEST_FAILED;
}

// Test 12: Permission denied for read
int test_permission_denied_read() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create file as root
	FSHandle f = fs_open("private_file.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	char data[] = "secret data";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Set permissions to no read for others
	cmd_chmod("private_file.txt", "rw-------");
	
	// Create non-root user and try to read
	cmd_useradd("noreaduser");
	if (!login_user("noreaduser", "noreaduser")) {
		return TEST_FAILED;
	}
	
	FSHandle f2 = fs_open("private_file.txt", 0); // No flags, just read
	// Should fail to open due to permission denied
	if (!f2.open) {
		return TEST_PASSED; // Expected to fail
	}
	
	fs_close(&f2);
	return TEST_FAILED;
}

// Test 13: Permission denied for write
int test_permission_denied_write() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create file as root
	FSHandle f = fs_open("readonly_file.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	// Set permissions to read-only for others
	cmd_chmod("readonly_file.txt", "rw-r--r--");
	
	// Create non-root user and try to write
	cmd_useradd("nowriteuser");
	if (!login_user("nowriteuser", "nowriteuser")) {
		return TEST_FAILED;
	}
	
	FSHandle f2 = fs_open("readonly_file.txt", 2); // WRITE flag
	// Should fail to open with write permission
	if (!f2.open) {
		return TEST_PASSED; // Expected to fail
	}
	
	fs_close(&f2);
	return TEST_FAILED;
}

// Test 14: Root bypasses permissions
int test_root_bypass() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create file with no permissions for others
	FSHandle f = fs_open("root_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	cmd_chmod("root_test.txt", "rw-------");
	
	// Root should still be able to read/write
	FSHandle f2 = fs_open("root_test.txt", 2); // WRITE
	if (f2.open) {
		fs_close(&f2);
		return TEST_PASSED;
	}
	
	return TEST_FAILED;
}

// Test 15: User deletion
int test_userdel() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("todelete");
	
	// Verify user exists
	User user_out;
	uint32_t offset;
	int found_before = find_user("todelete", &user_out, &offset);
	
	if (!found_before) {
		return TEST_FAILED;
	}
	
	cmd_userdel("todelete");
	
	// Verify user is deleted
	int found_after = find_user("todelete", &user_out, &offset);
	
	return found_after ? TEST_FAILED : TEST_PASSED;
}

// Test 16: Cannot delete root
int test_cannot_delete_root() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Try to delete root (should fail)
	cmd_userdel("root");
	
	// Root should still exist
	User user_out;
	uint32_t offset;
	int found = find_user("root", &user_out, &offset);
	
	return found ? TEST_PASSED : TEST_FAILED;
}

// Test 17: getfacl command
int test_getfacl() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("facl_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	cmd_chmod("facl_test.txt", "rwxr-xr-x");
	
	// getfacl should work without crashing
	cmd_getfacl("facl_test.txt");
	
	return TEST_PASSED;
}

// Test 18: chgrp command
int test_chgrp() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_groupadd("chgrptest");
	FSHandle f = fs_open("chgrp_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	cmd_chgrp("chgrp_test.txt", "chgrptest");
	
	// Check group was changed
	FileEntry entry_out;
	uint32_t offset;
	if (!find_file("chgrp_test.txt", &entry_out, &offset)) {
		return TEST_FAILED;
	}
	
	// Get group gid
	Group group_out;
	find_group("chgrptest", &group_out, &offset);
	uint32_t expected_gid = group_out.gid;
	
	if (entry_out.owner_gid == expected_gid) {
		return TEST_PASSED;
	}
	
	return TEST_FAILED;
}

// Test 19: su command
int test_su() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	cmd_useradd("sutest");
	
	// Root can switch without password
	if (su_user("sutest")) {
		if (get_current_uid() != 0 && strcmp(session.current_username, "sutest") == 0) {
			return TEST_PASSED;
		}
	}
	
	return TEST_FAILED;
}

// Test 20: File operations with permissions
int test_file_operations_permissions() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create file as root
	FSHandle f = fs_open("op_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	char data[] = "test data";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Set permissions
	cmd_chmod("op_test.txt", "rw-rw-r--");
	
	// Switch to non-root user
	cmd_useradd("opuser");
	if (!login_user("opuser", "opuser")) {
		return TEST_FAILED;
	}
	
	// Should be able to read (others have read)
	FSHandle f2 = fs_open("op_test.txt", 0);
	if (!f2.open) {
		return TEST_FAILED;
	}
	
	uint8_t buffer[32];
	int read_bytes = fs_read(&f2, 0, 32, buffer);
	if (read_bytes > 0) {
		fs_close(&f2);
		return TEST_PASSED;
	}
	
	fs_close(&f2);
	return TEST_FAILED;
}

// File Operation Tests

// Test 21: File creation
int test_file_creation() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("create_test.txt", 1 | 2); // CREATE | WRITE
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Check file exists
	FileEntry entry;
	if (!find_file("create_test.txt", &entry, NULL)) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 22: File write
int test_file_write() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("write_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	char data[] = "Hello, World!";
	int written = fs_write(&f, 0, strlen(data), (uint8_t*)data);
	
	if (written != (int)strlen(data)) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 23: File read
int test_file_read() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// First write some data
	FSHandle f1 = fs_open("read_test.txt", 1 | 2);
	if (!f1.open) {
		return TEST_FAILED;
	}
	
	char write_data[] = "Test read data";
	fs_write(&f1, 0, strlen(write_data), (uint8_t*)write_data);
	fs_close(&f1);
	
	// Now read it
	FSHandle f2 = fs_open("read_test.txt", 0); // Read only
	if (!f2.open) {
		return TEST_FAILED;
	}
	
	uint8_t buffer[32];
	int read_bytes = fs_read(&f2, 0, strlen(write_data), buffer);
	buffer[read_bytes] = '\0';
	
	if (read_bytes != (int)strlen(write_data) || strcmp((char*)buffer, write_data) != 0) {
		fs_close(&f2);
		return TEST_FAILED;
	}
	
	fs_close(&f2);
	return TEST_PASSED;
}

// Test 24: File write at specific position
int test_file_write_position() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("write_pos_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Write initial data
	char initial[] = "Hello";
	fs_write(&f, 0, strlen(initial), (uint8_t*)initial);
	
	// Write at position 6
	char append[] = "World";
	fs_write(&f, 6, strlen(append), (uint8_t*)append);
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 25: File read at specific position
int test_file_read_position() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("read_pos_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	char data[] = "ABCDEFGHIJ";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Read from position 5
	FSHandle f2 = fs_open("read_pos_test.txt", 0);
	uint8_t buffer[10];
	int read_bytes = fs_read(&f2, 5, 5, buffer);
	buffer[read_bytes] = '\0';
	
	if (read_bytes != 5 || buffer[0] != 'F') {
		fs_close(&f2);
		return TEST_FAILED;
	}
	
	fs_close(&f2);
	return TEST_PASSED;
}

// Test 26: File expansion on write
int test_file_expansion() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("expand_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Write initial small data
	char small[] = "Hi";
	fs_write(&f, 0, strlen(small), (uint8_t*)small);
	
	// Reload entry to get size
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	uint32_t initial_size = f.entry.size;
	
	// Write beyond current size
	char large[] = "This is a much longer string that will expand the file";
	fs_write(&f, 0, strlen(large), (uint8_t*)large);
	
	// Reload entry
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	
	if (f.entry.size <= initial_size) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 27: File deletion
int test_file_deletion() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create a file
	FSHandle f = fs_open("delete_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	fs_close(&f);
	
	// Verify it exists
	if (!find_file("delete_test.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Delete it
	fs_rm("delete_test.txt");
	
	// Verify it's gone
	if (find_file("delete_test.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 28: File shrink
int test_file_shrink() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("shrink_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Write large data
	char large[] = "This is a large string for shrinking test";
	fs_write(&f, 0, strlen(large), (uint8_t*)large);
	
	// Reload to get current size
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	uint32_t original_size = f.entry.size;
	
	// Shrink to smaller size
	fs_shrink(&f, 10);
	
	// Reload to verify
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	
	if (f.entry.size >= original_size || f.entry.size != 10) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 29: File open without create flag
int test_file_open_no_create() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Try to open non-existent file without CREATE flag
	FSHandle f = fs_open("nonexistent.txt", 0);
	if (f.open) {
		return TEST_FAILED; // Should not open
	}
	
	return TEST_PASSED;
}

// Test 30: File close
int test_file_close() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("close_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	fs_close(&f);
	
	if (f.open) {
		return TEST_FAILED; // Should be closed
	}
	
	return TEST_PASSED;
}

// Test 31: Multiple files
int test_multiple_files() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create multiple files
	FSHandle f1 = fs_open("multi1.txt", 1 | 2);
	FSHandle f2 = fs_open("multi2.txt", 1 | 2);
	FSHandle f3 = fs_open("multi3.txt", 1 | 2);
	
	if (!f1.open || !f2.open || !f3.open) {
		if (f1.open) fs_close(&f1);
		if (f2.open) fs_close(&f2);
		if (f3.open) fs_close(&f3);
		return TEST_FAILED;
	}
	
	// Write different data to each
	char data1[] = "File 1";
	char data2[] = "File 2";
	char data3[] = "File 3";
	
	fs_write(&f1, 0, strlen(data1), (uint8_t*)data1);
	fs_write(&f2, 0, strlen(data2), (uint8_t*)data2);
	fs_write(&f3, 0, strlen(data3), (uint8_t*)data3);
	
	fs_close(&f1);
	fs_close(&f2);
	fs_close(&f3);
	
	// Verify all exist
	if (!find_file("multi1.txt", NULL, NULL) ||
	    !find_file("multi2.txt", NULL, NULL) ||
	    !find_file("multi3.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 32: File statistics
int test_file_statistics() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("stat_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	char data[] = "Statistics test";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	
	// Check file entry has correct size
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	
	if (f.entry.size != strlen(data)) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	return TEST_PASSED;
}

// Test 33: Filesystem statistics
int test_fs_statistics() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create a few files
	FSHandle f1 = fs_open("fs_stat1.txt", 1 | 2);
	FSHandle f2 = fs_open("fs_stat2.txt", 1 | 2);
	
	if (!f1.open || !f2.open) {
		if (f1.open) fs_close(&f1);
		if (f2.open) fs_close(&f2);
		return TEST_FAILED;
	}
	
	char data[] = "Test";
	fs_write(&f1, 0, strlen(data), (uint8_t*)data);
	fs_write(&f2, 0, strlen(data), (uint8_t*)data);
	
	fs_close(&f1);
	fs_close(&f2);
	
	// fs_stats() should work without crashing
	fs_stats();
	
	return TEST_PASSED;
}

// Test 34: Read beyond file size
int test_read_beyond_size() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("beyond_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	char data[] = "Small";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Try to read beyond file size
	FSHandle f2 = fs_open("beyond_test.txt", 0);
	uint8_t buffer[100];
	int read_bytes = fs_read(&f2, 100, 50, buffer); // Read from position 100
	
	// Should return 0 (no bytes read) or handle gracefully
	if (read_bytes < 0) {
		fs_close(&f2);
		return TEST_FAILED;
	}
	
	fs_close(&f2);
	return TEST_PASSED;
}

// Test 35: File handle management
int test_file_handle_management() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create and close multiple handles
	FSHandle f1 = fs_open("handle1.txt", 1 | 2);
	if (!f1.open) {
		return TEST_FAILED;
	}
	fs_close(&f1);
	
	FSHandle f2 = fs_open("handle2.txt", 1 | 2);
	if (!f2.open) {
		return TEST_FAILED;
	}
	fs_close(&f2);
	
	// Reopen same file
	FSHandle f3 = fs_open("handle1.txt", 0);
	if (!f3.open) {
		return TEST_FAILED;
	}
	fs_close(&f3);
	
	return TEST_PASSED;
}

// Complex Integration Tests

// Test 36: Write, delete, and verify file is gone
int test_write_delete_verify() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create and write to file
	FSHandle f = fs_open("writedel_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	char data[] = "This file will be deleted";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Verify file exists and has correct content
	FSHandle f2 = fs_open("writedel_test.txt", 0);
	if (!f2.open) {
		return TEST_FAILED;
	}
	
	uint8_t buffer[64];
	int read_bytes = fs_read(&f2, 0, strlen(data), buffer);
	buffer[read_bytes] = '\0';
	
	if (strcmp((char*)buffer, data) != 0) {
		fs_close(&f2);
		return TEST_FAILED;
	}
	fs_close(&f2);
	
	// Delete the file
	fs_rm("writedel_test.txt");
	
	// Verify file no longer exists
	if (find_file("writedel_test.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify we cannot open it
	FSHandle f3 = fs_open("writedel_test.txt", 0);
	if (f3.open) {
		fs_close(&f3);
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 37: Multiple write and delete operations
int test_multiple_write_delete() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create multiple files
	const char* files[] = {"multi_del1.txt", "multi_del2.txt", "multi_del3.txt", "multi_del4.txt"};
	const char* contents[] = {"Content 1", "Content 2", "Content 3", "Content 4"};
	
	// Write all files
	for (int i = 0; i < 4; i++) {
		FSHandle f = fs_open(files[i], 1 | 2);
		if (!f.open) {
			return TEST_FAILED;
		}
		fs_write(&f, 0, strlen(contents[i]), (uint8_t*)contents[i]);
		fs_close(&f);
	}
	
	// Verify all exist
	for (int i = 0; i < 4; i++) {
		if (!find_file(files[i], NULL, NULL)) {
			return TEST_FAILED;
		}
	}
	
	// Delete middle files
	fs_rm(files[1]);
	fs_rm(files[2]);
	
	// Verify deleted files are gone
	if (find_file(files[1], NULL, NULL) || find_file(files[2], NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify remaining files still exist and have correct content
	for (int i = 0; i < 4; i += 3) { // Check files 0 and 3
		FSHandle f = fs_open(files[i], 0);
		if (!f.open) {
			return TEST_FAILED;
		}
		uint8_t buffer[32];
		int read_bytes = fs_read(&f, 0, strlen(contents[i]), buffer);
		buffer[read_bytes] = '\0';
		if (strcmp((char*)buffer, contents[i]) != 0) {
			fs_close(&f);
			return TEST_FAILED;
		}
		fs_close(&f);
	}
	
	return TEST_PASSED;
}

// Test 38: File chain integrity after deletion
int test_file_chain_integrity() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create chain of files
	FSHandle f1 = fs_open("chain1.txt", 1 | 2);
	FSHandle f2 = fs_open("chain2.txt", 1 | 2);
	FSHandle f3 = fs_open("chain3.txt", 1 | 2);
	FSHandle f4 = fs_open("chain4.txt", 1 | 2);
	
	if (!f1.open || !f2.open || !f3.open || !f4.open) {
		if (f1.open) fs_close(&f1);
		if (f2.open) fs_close(&f2);
		if (f3.open) fs_close(&f3);
		if (f4.open) fs_close(&f4);
		return TEST_FAILED;
	}
	
	fs_write(&f1, 0, 5, (uint8_t*)"File1");
	fs_write(&f2, 0, 5, (uint8_t*)"File2");
	fs_write(&f3, 0, 5, (uint8_t*)"File3");
	fs_write(&f4, 0, 5, (uint8_t*)"File4");
	
	fs_close(&f1);
	fs_close(&f2);
	fs_close(&f3);
	fs_close(&f4);
	
	// Delete middle file (chain2.txt)
	fs_rm("chain2.txt");
	
	// Verify chain integrity - all remaining files should be accessible
	const char* remaining[] = {"chain1.txt", "chain3.txt", "chain4.txt"};
	for (int i = 0; i < 3; i++) {
		if (!find_file(remaining[i], NULL, NULL)) {
			return TEST_FAILED;
		}
		FSHandle f = fs_open(remaining[i], 0);
		if (!f.open) {
			return TEST_FAILED;
		}
		fs_close(&f);
	}
	
	return TEST_PASSED;
}

// Test 39: Large file write and delete
int test_large_file_operations() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	FSHandle f = fs_open("large_file.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Write large amount of data (multiple blocks)
	char large_data[512];
	for (int i = 0; i < 512; i++) {
		large_data[i] = 'A' + (i % 26);
	}
	
	int written = fs_write(&f, 0, 512, (uint8_t*)large_data);
	if (written != 512) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	// Verify size
	fseek(disk, f.offset_in_fs, SEEK_SET);
	fread(&f.entry, sizeof(FileEntry), 1, disk);
	if (f.entry.size != 512) {
		fs_close(&f);
		return TEST_FAILED;
	}
	
	fs_close(&f);
	
	// Verify we can read it back
	FSHandle f2 = fs_open("large_file.txt", 0);
	if (!f2.open) {
		return TEST_FAILED;
	}
	
	uint8_t read_buffer[512];
	int read_bytes = fs_read(&f2, 0, 512, read_buffer);
	if (read_bytes != 512) {
		fs_close(&f2);
		return TEST_FAILED;
	}
	
	// Verify content
	for (int i = 0; i < 512; i++) {
		if (read_buffer[i] != large_data[i]) {
			fs_close(&f2);
			return TEST_FAILED;
		}
	}
	fs_close(&f2);
	
	// Delete large file
	fs_rm("large_file.txt");
	
	// Verify it's gone
	if (find_file("large_file.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 40: Sequential write, delete, write operations
int test_sequential_write_delete() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	const char* filename = "sequential_test.txt";
	
	// First write
	FSHandle f1 = fs_open(filename, 1 | 2);
	if (!f1.open) {
		return TEST_FAILED;
	}
	char data1[] = "First write";
	fs_write(&f1, 0, strlen(data1), (uint8_t*)data1);
	fs_close(&f1);
	
	// Verify first write
	FSHandle f1_read = fs_open(filename, 0);
	uint8_t buffer1[32];
	fs_read(&f1_read, 0, strlen(data1), buffer1);
	buffer1[strlen(data1)] = '\0';
	if (strcmp((char*)buffer1, data1) != 0) {
		fs_close(&f1_read);
		return TEST_FAILED;
	}
	fs_close(&f1_read);
	
	// Delete
	fs_rm(filename);
	
	// Verify deleted
	if (find_file(filename, NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Second write (recreate)
	FSHandle f2 = fs_open(filename, 1 | 2);
	if (!f2.open) {
		return TEST_FAILED;
	}
	char data2[] = "Second write";
	fs_write(&f2, 0, strlen(data2), (uint8_t*)data2);
	fs_close(&f2);
	
	// Verify second write
	FSHandle f2_read = fs_open(filename, 0);
	uint8_t buffer2[32];
	fs_read(&f2_read, 0, strlen(data2), buffer2);
	buffer2[strlen(data2)] = '\0';
	if (strcmp((char*)buffer2, data2) != 0) {
		fs_close(&f2_read);
		return TEST_FAILED;
	}
	fs_close(&f2_read);
	
	return TEST_PASSED;
}

// Test 41: Delete and recreate same file
int test_delete_recreate() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	const char* filename = "recreate_test.txt";
	
	// Create file
	FSHandle f1 = fs_open(filename, 1 | 2);
	if (!f1.open) {
		return TEST_FAILED;
	}
	char original[] = "Original content";
	fs_write(&f1, 0, strlen(original), (uint8_t*)original);
	fs_close(&f1);
	
	// Delete
	fs_rm(filename);
	
	// Immediately recreate with different content
	FSHandle f2 = fs_open(filename, 1 | 2);
	if (!f2.open) {
		return TEST_FAILED;
	}
	char new_content[] = "New content after delete";
	fs_write(&f2, 0, strlen(new_content), (uint8_t*)new_content);
	fs_close(&f2);
	
	// Verify new content
	FSHandle f3 = fs_open(filename, 0);
	uint8_t buffer[64];
	int read_bytes = fs_read(&f3, 0, strlen(new_content), buffer);
	buffer[read_bytes] = '\0';
	
	if (strcmp((char*)buffer, new_content) != 0) {
		fs_close(&f3);
		return TEST_FAILED;
	}
	
	// Verify old content is gone
	if (strstr((char*)buffer, original) != NULL) {
		fs_close(&f3);
		return TEST_FAILED;
	}
	
	fs_close(&f3);
	return TEST_PASSED;
}

// Test 42: Filesystem consistency check
int test_fs_consistency() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create several files
	const char* files[] = {"consist1.txt", "consist2.txt", "consist3.txt"};
	
	for (int i = 0; i < 3; i++) {
		FSHandle f = fs_open(files[i], 1 | 2);
		if (!f.open) {
			return TEST_FAILED;
		}
		char data[32];
		sprintf(data, "File %d content", i+1);
		fs_write(&f, 0, strlen(data), (uint8_t*)data);
		fs_close(&f);
	}
	
	// Delete middle file
	fs_rm(files[1]);
	
	// Verify filesystem can still enumerate remaining files using dirents
	int found_count = 0;
	if (meta.root_dirent_offset != 0) {
		FileEntry root_entry;
		fseek(disk, meta.root_dirent_offset, SEEK_SET);
		fread(&root_entry, sizeof(FileEntry), 1, disk);
		
		// Read root dirent data
		DirentData root_data;
		fseek(disk, root_entry.start, SEEK_SET);
		fread(&root_data, sizeof(DirentData), 1, disk);
		
		// Check all children in root dirent
		for (uint32_t i = 0; i < root_data.child_count; i++) {
			FileEntry e;
			fseek(disk, root_data.children[i], SEEK_SET);
			fread(&e, sizeof(FileEntry), 1, disk);
			
				// Check if this is one of our test files
			for (int j = 0; j < 3; j++) {
				if (j != 1 && strcmp(e.name, files[j]) == 0) {
					found_count++;
				}
			}
		}
	}
	
	// Should find 2 files (files[0] and files[2])
	if (found_count != 2) {
		return TEST_FAILED;
	}
	
	// Verify deleted file is not in root dirent
	if (meta.root_dirent_offset != 0) {
		FileEntry root_entry;
		fseek(disk, meta.root_dirent_offset, SEEK_SET);
		fread(&root_entry, sizeof(FileEntry), 1, disk);
		
		DirentData root_data;
		fseek(disk, root_entry.start, SEEK_SET);
		fread(&root_data, sizeof(DirentData), 1, disk);
		
		// Check that deleted file is not in children
		for (uint32_t i = 0; i < root_data.child_count; i++) {
			FileEntry e;
			fseek(disk, root_data.children[i], SEEK_SET);
			fread(&e, sizeof(FileEntry), 1, disk);
			
			if (strcmp(e.name, files[1]) == 0) {
				return TEST_FAILED;  // Deleted file still found
			}
		}
	}
	
	return TEST_PASSED;
}

// Test 43: Free block recovery after delete
int test_free_block_recovery() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create a file with significant data
	FSHandle f = fs_open("freeblock_test.txt", 1 | 2);
	if (!f.open) {
		return TEST_FAILED;
	}
	
	// Write data that uses multiple blocks
	char data[256];
	for (int i = 0; i < 256; i++) {
		data[i] = 'X';
	}
	fs_write(&f, 0, 256, (uint8_t*)data);
	
	fs_close(&f);
	
	// Delete file
	fs_rm("freeblock_test.txt");
	
	// Verify file is deleted
	if (find_file("freeblock_test.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// The blocks should be freed and available for reuse
	// Create new file - it might reuse the freed blocks
	FSHandle f2 = fs_open("reuse_test.txt", 1 | 2);
	if (!f2.open) {
		return TEST_FAILED;
	}
	
	char new_data[] = "Reused blocks";
	fs_write(&f2, 0, strlen(new_data), (uint8_t*)new_data);
	fs_close(&f2);
	
	// Verify new file works correctly
	FSHandle f3 = fs_open("reuse_test.txt", 0);
	uint8_t buffer[32];
	fs_read(&f3, 0, strlen(new_data), buffer);
	buffer[strlen(new_data)] = '\0';
	
	if (strcmp((char*)buffer, new_data) != 0) {
		fs_close(&f3);
		return TEST_FAILED;
	}
	
	fs_close(&f3);
	return TEST_PASSED;
}

// Test 44: Complex multi-file scenario
int test_complex_multifile() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create 5 files
	const char* files[] = {"complex1.txt", "complex2.txt", "complex3.txt", "complex4.txt", "complex5.txt"};
	const char* contents[] = {"One", "Two", "Three", "Four", "Five"};
	
	// Create all files
	for (int i = 0; i < 5; i++) {
		FSHandle f = fs_open(files[i], 1 | 2);
		if (!f.open) {
			return TEST_FAILED;
		}
		fs_write(&f, 0, strlen(contents[i]), (uint8_t*)contents[i]);
		fs_close(&f);
	}
	
	// Verify all exist
	for (int i = 0; i < 5; i++) {
		if (!find_file(files[i], NULL, NULL)) {
			return TEST_FAILED;
		}
	}
	
	// Delete files 1, 3, 5 (alternating)
	fs_rm(files[0]);
	fs_rm(files[2]);
	fs_rm(files[4]);
	
	// Verify deleted files are gone
	if (find_file(files[0], NULL, NULL) ||
	    find_file(files[2], NULL, NULL) ||
	    find_file(files[4], NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify remaining files (2 and 4) still have correct content
	for (int i = 1; i < 5; i += 2) {
		FSHandle f = fs_open(files[i], 0);
		if (!f.open) {
			return TEST_FAILED;
		}
		uint8_t buffer[32];
		int read_bytes = fs_read(&f, 0, strlen(contents[i]), buffer);
		buffer[read_bytes] = '\0';
		if (strcmp((char*)buffer, contents[i]) != 0) {
			fs_close(&f);
			return TEST_FAILED;
		}
		fs_close(&f);
	}
	
	// Create new files with same names as deleted ones
	FSHandle f_new1 = fs_open(files[0], 1 | 2);
	FSHandle f_new3 = fs_open(files[2], 1 | 2);
	
	if (!f_new1.open || !f_new3.open) {
		if (f_new1.open) fs_close(&f_new1);
		if (f_new3.open) fs_close(&f_new3);
		return TEST_FAILED;
	}
	
	char new_content1[] = "New One";
	char new_content3[] = "New Three";
	fs_write(&f_new1, 0, strlen(new_content1), (uint8_t*)new_content1);
	fs_write(&f_new3, 0, strlen(new_content3), (uint8_t*)new_content3);
	fs_close(&f_new1);
	fs_close(&f_new3);
	
	// Verify new files have new content
	FSHandle f_check1 = fs_open(files[0], 0);
	uint8_t buffer1[32];
	fs_read(&f_check1, 0, strlen(new_content1), buffer1);
	buffer1[strlen(new_content1)] = '\0';
	if (strcmp((char*)buffer1, new_content1) != 0) {
		fs_close(&f_check1);
		return TEST_FAILED;
	}
	fs_close(&f_check1);
	
	return TEST_PASSED;
}

// Test 44: mkdir command
int test_mkdir() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create a directory
	uint32_t dir_offset = create_dirent("testdir", meta.root_dirent_offset);
	if (dir_offset == 0) {
		return TEST_FAILED;
	}
	
	// Verify directory exists
	FileEntry dir_entry;
	if (!find_file("testdir", &dir_entry, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify it's a dirent
	if (!is_dirent(&dir_entry)) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 45: cd command (path resolution)
int test_cd_path_resolution() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create a directory
	uint32_t dir_offset = create_dirent("testdir2", meta.root_dirent_offset);
	if (dir_offset == 0) {
		return TEST_FAILED;
	}
	
	// Test resolving absolute path
	FileEntry resolved;
	uint32_t resolved_offset;
	uint32_t parent_offset;
	if (!resolve_path("/testdir2", meta.root_dirent_offset, &resolved_offset, &resolved, &parent_offset)) {
		return TEST_FAILED;
	}
	
	if (resolved_offset != dir_offset) {
		return TEST_FAILED;
	}
	
	if (!is_dirent(&resolved)) {
		return TEST_FAILED;
	}
	
	// Test resolving relative path
	if (!resolve_path("testdir2", meta.root_dirent_offset, &resolved_offset, &resolved, &parent_offset)) {
		return TEST_FAILED;
	}
	
	if (resolved_offset != dir_offset) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 46: ls command (list directory)
int test_ls_list_directory() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create some files in root
	FSHandle f1 = fs_open("ls_test1.txt", CREATE | WRITE);
	FSHandle f2 = fs_open("ls_test2.txt", CREATE | WRITE);
	if (!f1.open || !f2.open) {
		if (f1.open) fs_close(&f1);
		if (f2.open) fs_close(&f2);
		return TEST_FAILED;
	}
	fs_close(&f1);
	fs_close(&f2);
	
	// Read root dirent
	if (meta.root_dirent_offset == 0) {
		return TEST_FAILED;
	}
	
	DirentData root_data;
	if (!read_dirent(meta.root_dirent_offset, &root_data)) {
		return TEST_FAILED;
	}
	
	// Count files we created
	int found_count = 0;
	for (uint32_t i = 0; i < root_data.child_count; i++) {
		FileEntry e;
		fseek(disk, root_data.children[i], SEEK_SET);
		fread(&e, sizeof(FileEntry), 1, disk);
		if (strcmp(e.name, "ls_test1.txt") == 0 || strcmp(e.name, "ls_test2.txt") == 0) {
			found_count++;
		}
	}
	
	if (found_count != 2) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 47: cp command
int test_cp_command() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create source file
	FSHandle src = fs_open("cp_source.txt", CREATE | WRITE);
	if (!src.open) {
		return TEST_FAILED;
	}
	char src_data[] = "Source file content";
	fs_write(&src, 0, strlen(src_data), (uint8_t*)src_data);
	fs_close(&src);
	
	// Copy file
	if (!fs_cp("cp_source.txt", "cp_dest.txt", meta.root_dirent_offset, 0)) {
		return TEST_FAILED;
	}
	
	// Verify destination exists
	FileEntry dest_entry;
	if (!find_file("cp_dest.txt", &dest_entry, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify content matches
	FSHandle dest = fs_open("cp_dest.txt", 0);
	if (!dest.open) {
		return TEST_FAILED;
	}
	
	uint8_t buffer[64];
	int read_bytes = fs_read(&dest, 0, strlen(src_data), buffer);
	buffer[read_bytes] = '\0';
	fs_close(&dest);
	
	if (read_bytes != (int)strlen(src_data) || strcmp((char*)buffer, src_data) != 0) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 48: mv command
int test_mv_command() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create source file
	FSHandle src = fs_open("mv_source.txt", CREATE | WRITE);
	if (!src.open) {
		return TEST_FAILED;
	}
	char src_data[] = "Move test content";
	fs_write(&src, 0, strlen(src_data), (uint8_t*)src_data);
	fs_close(&src);
	
	// Verify source exists
	if (!find_file("mv_source.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Move file
	if (!fs_mv("mv_source.txt", "mv_dest.txt", meta.root_dirent_offset, 0)) {
		return TEST_FAILED;
	}
	
	// Verify source no longer exists
	if (find_file("mv_source.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify destination exists
	FileEntry dest_entry;
	if (!find_file("mv_dest.txt", &dest_entry, NULL)) {
		return TEST_FAILED;
	}
	
	// Verify content matches
	FSHandle dest = fs_open("mv_dest.txt", 0);
	if (!dest.open) {
		return TEST_FAILED;
	}
	
	uint8_t buffer[64];
	int read_bytes = fs_read(&dest, 0, strlen(src_data), buffer);
	buffer[read_bytes] = '\0';
	fs_close(&dest);
	
	if (read_bytes != (int)strlen(src_data) || strcmp((char*)buffer, src_data) != 0) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

// Test 49: Nested directories
int test_nested_directories() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	// Create parent directory
	uint32_t parent_offset = create_dirent("parent", meta.root_dirent_offset);
	if (parent_offset == 0) {
		return TEST_FAILED;
	}
	
	// Create child directory
	uint32_t child_offset = create_dirent("child", parent_offset);
	if (child_offset == 0) {
		return TEST_FAILED;
	}
	
	// Verify nested path resolution
	FileEntry resolved;
	uint32_t resolved_offset;
	if (!resolve_path("/parent/child", meta.root_dirent_offset, &resolved_offset, &resolved, NULL)) {
		return TEST_FAILED;
	}
	
	if (resolved_offset != child_offset) {
		return TEST_FAILED;
	}
	
	// Create file in nested directory
	FSHandle f = fs_open("/parent/child/nested_file.txt", CREATE | WRITE);
	if (!f.open) {
		return TEST_FAILED;
	}
	char data[] = "Nested file";
	fs_write(&f, 0, strlen(data), (uint8_t*)data);
	fs_close(&f);
	
	// Verify file exists at nested path
	if (!find_file("/parent/child/nested_file.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

int test_e2e_workflow() {
	if (!is_root()) {
		login_user("root", "root");
	}
	
	printf("\n=== E2E Test: Complete Real-World Workflow ===\n");
	
	cmd_useradd("alice");
	cmd_useradd("bob");
	cmd_useradd("charlie");
	cmd_groupadd("developers");
	cmd_groupadd("managers");
	cmd_groupadd("qa");
	
	cmd_usermod("alice", "developers");
	cmd_usermod("bob", "developers");
	cmd_usermod("alice", "managers");
	cmd_usermod("charlie", "qa");
	
	if (!login_user("alice", "alice")) {
		return TEST_FAILED;
	}
	
	FSHandle f1 = fs_open("project_plan.txt", 1 | 2);
	if (!f1.open) {
		return TEST_FAILED;
	}
	char plan[] = "Project Plan:\n1. Design\n2. Implement\n3. Test\n4. Deploy";
	fs_write(&f1, 0, strlen(plan), (uint8_t*)plan);
	fs_close(&f1);
	
	FSHandle f2 = fs_open("private_notes.txt", 1 | 2);
	if (!f2.open) {
		return TEST_FAILED;
	}
	char notes[] = "Confidential meeting notes";
	fs_write(&f2, 0, strlen(notes), (uint8_t*)notes);
	fs_close(&f2);
	
	FSHandle f3 = fs_open("shared_doc.txt", 1 | 2);
	if (!f3.open) {
		return TEST_FAILED;
	}
	char shared[] = "Shared document for team";
	fs_write(&f3, 0, strlen(shared), (uint8_t*)shared);
	fs_close(&f3);
	
	cmd_chmod("project_plan.txt", "rw-rw-r--");
	cmd_chmod("private_notes.txt", "rw-------");
	cmd_chmod("shared_doc.txt", "rwxrwxr-x");
	
	if (!login_user("bob", "bob")) {
		return TEST_FAILED;
	}
	
	FSHandle f4 = fs_open("project_plan.txt", 0);
	if (!f4.open) {
		return TEST_FAILED;
	}
	uint8_t buffer1[256];
	int read1 = fs_read(&f4, 0, strlen(plan), buffer1);
	buffer1[read1] = '\0';
	if (strcmp((char*)buffer1, plan) != 0) {
		fs_close(&f4);
		return TEST_FAILED;
	}
	fs_close(&f4);
	
	FSHandle f5 = fs_open("private_notes.txt", 0);
	if (f5.open) {
		fs_close(&f5);
		return TEST_FAILED;
	}
	
	FSHandle f6 = fs_open("shared_doc.txt", 0);
	if (!f6.open) {
		return TEST_FAILED;
	}
	uint8_t buffer2[64];
	int read2 = fs_read(&f6, 0, strlen(shared), buffer2);
	buffer2[read2] = '\0';
	if (strcmp((char*)buffer2, shared) != 0) {
		fs_close(&f6);
		return TEST_FAILED;
	}
	fs_close(&f6);
	
	FSHandle f7 = fs_open("bob_implementation.txt", 1 | 2);
	if (!f7.open) {
		return TEST_FAILED;
	}
	char bob_code[] = "Bob's code implementation\nLine 1\nLine 2\nLine 3";
	fs_write(&f7, 0, strlen(bob_code), (uint8_t*)bob_code);
	fs_close(&f7);
	
	cmd_chmod("bob_implementation.txt", "rw-rw-r--");
	
	if (!login_user("root", "root")) {
		return TEST_FAILED;
	}
	
	cmd_chown("bob_implementation.txt", "alice:developers");
	
	if (!login_user("alice", "alice")) {
		return TEST_FAILED;
	}
	
	FSHandle f8 = fs_open("bob_implementation.txt", 0);
	if (!f8.open) {
		return TEST_FAILED;
	}
	uint8_t buffer3[128];
	int read3 = fs_read(&f8, 0, strlen(bob_code), buffer3);
	buffer3[read3] = '\0';
	if (strcmp((char*)buffer3, bob_code) != 0) {
		fs_close(&f8);
		return TEST_FAILED;
	}
	fs_close(&f8);
	
	FSHandle f9 = fs_open("bob_implementation.txt", 2);
	if (!f9.open) {
		return TEST_FAILED;
	}
	char alice_review[] = "\n\n--- Review by Alice ---\nApproved with minor changes";
	fs_write(&f9, strlen(bob_code), strlen(alice_review), (uint8_t*)alice_review);
	fs_close(&f9);
	
	FSHandle f10 = fs_open("alice_report.txt", 1 | 2);
	if (!f10.open) {
		return TEST_FAILED;
	}
	char report[] = "Monthly Report\nStatus: On Track";
	fs_write(&f10, 0, strlen(report), (uint8_t*)report);
	fs_close(&f10);
	
	if (!login_user("bob", "bob")) {
		return TEST_FAILED;
	}
	
	FSHandle f11 = fs_open("bob_implementation.txt", 0);
	if (!f11.open) {
		return TEST_FAILED;
	}
	uint8_t buffer4[256];
	int read4 = fs_read(&f11, 0, strlen(bob_code) + strlen(alice_review), buffer4);
	buffer4[read4] = '\0';
	if (strstr((char*)buffer4, alice_review) == NULL) {
		fs_close(&f11);
		return TEST_FAILED;
	}
	fs_close(&f11);
	
	FSHandle f12 = fs_open("alice_report.txt", 0);
	if (!f12.open) {
		return TEST_FAILED;
	}
	fs_close(&f12);
	
	if (!login_user("charlie", "charlie")) {
		return TEST_FAILED;
	}
	
	FSHandle f13 = fs_open("test_plan.txt", 1 | 2);
	if (!f13.open) {
		return TEST_FAILED;
	}
	char test_plan[] = "Test Plan:\n1. Unit tests\n2. Integration tests\n3. E2E tests";
	fs_write(&f13, 0, strlen(test_plan), (uint8_t*)test_plan);
	fs_close(&f13);
	
	if (!login_user("root", "root")) {
		return TEST_FAILED;
	}
	
	fs_rm("private_notes.txt");
	
	if (find_file("private_notes.txt", NULL, NULL)) {
		return TEST_FAILED;
	}
	
	FileEntry e1, e2, e3, e4, e5;
	if (!find_file("project_plan.txt", &e1, NULL) ||
	    !find_file("shared_doc.txt", &e2, NULL) ||
	    !find_file("bob_implementation.txt", &e3, NULL) ||
	    !find_file("alice_report.txt", &e4, NULL) ||
	    !find_file("test_plan.txt", &e5, NULL)) {
		return TEST_FAILED;
	}
	
	if (e1.owner_uid == 0 || e3.owner_uid == 0 || e4.owner_uid == 0 || e5.owner_uid == 0) {
		return TEST_FAILED;
	}
	
	if (!login_user("alice", "alice")) {
		return TEST_FAILED;
	}
	
	FSHandle f14 = fs_open("project_plan.txt", 2);
	if (!f14.open) {
		return TEST_FAILED;
	}
	char update[] = "\n5. Maintenance";
	fs_write(&f14, strlen(plan), strlen(update), (uint8_t*)update);
	fs_close(&f14);
	
	FSHandle f15 = fs_open("project_plan.txt", 0);
	uint8_t buffer5[256];
	int read5 = fs_read(&f15, 0, strlen(plan) + strlen(update), buffer5);
	buffer5[read5] = '\0';
	if (strstr((char*)buffer5, update) == NULL) {
		fs_close(&f15);
		return TEST_FAILED;
	}
	fs_close(&f15);
	
	if (!login_user("bob", "bob")) {
		return TEST_FAILED;
	}
	
	FSHandle f16 = fs_open("project_plan.txt", 0);
	uint8_t buffer6[256];
	int read6 = fs_read(&f16, 0, strlen(plan) + strlen(update), buffer6);
	buffer6[read6] = '\0';
	if (strstr((char*)buffer6, update) == NULL) {
		fs_close(&f16);
		return TEST_FAILED;
	}
	fs_close(&f16);
	
	if (!login_user("root", "root")) {
		return TEST_FAILED;
	}
	
	fs_stats();
	
	FileEntry final_check;
	if (!find_file("project_plan.txt", &final_check, NULL)) {
		return TEST_FAILED;
	}
	
	if (final_check.size != strlen(plan) + strlen(update)) {
		return TEST_FAILED;
	}
	
	printf("=== E2E Test Completed Successfully ===\n");
	
	return TEST_PASSED;
}

static void cleanup_test_files() {
	if (!is_root()) {
		login_user("root", "root");
	}
	for (int p = 0; p < CONCURRENT_NUM_PROCESSES; p++) {
		for (int i = 0; i < CONCURRENT_NUM_OPERATIONS + 10; i++) {
			char filename[64];
			snprintf(filename, sizeof(filename), "concurrent_test_%d_%d", p, i);
			fs_rm(filename);
			snprintf(filename, sizeof(filename), "concurrent_lost_%d_%d", p, i);
			fs_rm(filename);
			snprintf(filename, sizeof(filename), "concurrent_bitmap_%d_%d", p, i);
			fs_rm(filename);
		}
	}
	fs_rm("concurrent_shared.txt");
	for (int i = 0; i < 20; i++) {
		char filename[64];
		snprintf(filename, sizeof(filename), "concurrent_delete_%d", i);
		fs_rm(filename);
	}
}

static int run_concurrent_test(void (*test_func)(int), const char *test_name __attribute__((unused))) {
	cleanup_test_files();
	
	pid_t pids[CONCURRENT_NUM_PROCESSES];
	
	for (int i = 0; i < CONCURRENT_NUM_PROCESSES; i++) {
		pids[i] = fork();
		
		if (pids[i] == 0) {
			if (disk) fclose(disk);
			disk = fopen(FS_FILENAME, "r+b");
			if (!disk) {
				exit(1);
			}
			read_metadata();
			
			test_func(i);
			
			if (disk) fclose(disk);
			exit(0);
		} else if (pids[i] < 0) {
			return TEST_FAILED;
		}
	}
	
	int all_success = 1;
	for (int i = 0; i < CONCURRENT_NUM_PROCESSES; i++) {
		int status;
		pid_t waited = waitpid(pids[i], &status, 0);
		if (waited <= 0 || WEXITSTATUS(status) != 0) {
			all_success = 0;
		}
	}
	
	if (disk) fclose(disk);
	disk = fopen(FS_FILENAME, "r+b");
	read_metadata();
	
	if (!all_success) {
		return TEST_FAILED;
	}
	
	// Count files using dirents
	uint32_t file_count = 0;
	if (meta.root_dirent_offset != 0) {
		FileEntry root_entry;
		fseek(disk, meta.root_dirent_offset, SEEK_SET);
		if (fread(&root_entry, sizeof(FileEntry), 1, disk) == 1) {
			DirentData root_data;
			fseek(disk, root_entry.start, SEEK_SET);
			if (fread(&root_data, sizeof(DirentData), 1, disk) == 1) {
				file_count = root_data.child_count;
			}
		}
	}
	
	if (file_count == 0) {
		return TEST_FAILED;
	}
	
	return TEST_PASSED;
}

static void concurrent_test_lost_file_entry(int process_id) {
	if (!login_user("root", "root")) {
		return;
	}
	
	for (int i = 0; i < CONCURRENT_NUM_OPERATIONS; i++) {
		char filename[64];
		snprintf(filename, sizeof(filename), "concurrent_lost_%d_%d", process_id, i);
		
		FSHandle f = fs_open(filename, CREATE | WRITE);
		if (f.open) {
			char data[32];
			snprintf(data, sizeof(data), "Test %d", i);
			fs_write(&f, 0, strlen(data), (uint8_t*)data);
			fs_close(&f);
		}
		usleep(CONCURRENT_RACE_DELAY_US);
	}
}

static void concurrent_test_bitmap_stress(int process_id) {
	if (!login_user("root", "root")) {
		return;
	}
	
	for (int i = 0; i < CONCURRENT_NUM_OPERATIONS; i++) {
		char filename[64];
		snprintf(filename, sizeof(filename), "concurrent_bitmap_%d_%d", process_id, i);
		
		FSHandle f = fs_open(filename, CREATE | WRITE);
		if (f.open) {
			char data[16];
			snprintf(data, sizeof(data), "B%d", i);
			fs_write(&f, 0, strlen(data), (uint8_t*)data);
			fs_close(&f);
		}
		usleep(CONCURRENT_RACE_DELAY_US / 2);
	}
}

static void concurrent_test_concurrent_write(int process_id) {
	if (!login_user("root", "root")) {
		return;
	}
	
	FSHandle f = fs_open("concurrent_shared.txt", CREATE | WRITE);
	if (!f.open) {
		f = fs_open("concurrent_shared.txt", WRITE);
	}
	
	if (f.open) {
		for (int i = 0; i < 5; i++) {
			char data[64];
			snprintf(data, sizeof(data), "Write from process %d, iteration %d\n", process_id, i);
			uint32_t pos = process_id * 1000 + i * 100;
			fs_write(&f, pos, strlen(data), (uint8_t*)data);
			usleep(CONCURRENT_RACE_DELAY_US);
		}
		fs_close(&f);
	}
}

static void concurrent_test_deletion_race(int process_id) {
	if (!login_user("root", "root")) {
		return;
	}
	
	if (process_id == 0) {
		for (int i = 0; i < 10; i++) {
			char filename[64];
			snprintf(filename, sizeof(filename), "concurrent_delete_%d", i);
			
			FSHandle f = fs_open(filename, CREATE | WRITE);
			if (f.open) {
				char data[32];
				snprintf(data, sizeof(data), "Data %d", i);
				fs_write(&f, 0, strlen(data), (uint8_t*)data);
				uint8_t buffer[64];
				fs_read(&f, 0, 32, buffer);
				fs_close(&f);
			}
			usleep(CONCURRENT_RACE_DELAY_US * 2);
		}
	} else {
		for (int i = 0; i < 10; i++) {
			char filename[64];
			snprintf(filename, sizeof(filename), "concurrent_delete_%d", i);
			fs_rm(filename);
			usleep(CONCURRENT_RACE_DELAY_US);
		}
	}
}

int test_concurrent_file_creation() {
	return run_concurrent_test(concurrent_test_lost_file_entry, "Concurrent file creation");
}

int test_concurrent_bitmap_operations() {
	return run_concurrent_test(concurrent_test_bitmap_stress, "Concurrent bitmap operations");
}

int test_concurrent_write_operations() {
	return run_concurrent_test(concurrent_test_concurrent_write, "Concurrent write operations");
}

int test_concurrent_deletion_race() {
	return run_concurrent_test(concurrent_test_deletion_race, "Concurrent deletion race");
}

int test_concurrent_mixed_operations() {
	cleanup_test_files();
	
	pid_t pids[CONCURRENT_NUM_PROCESSES];
	
	for (int i = 0; i < CONCURRENT_NUM_PROCESSES; i++) {
		pids[i] = fork();
		
		if (pids[i] == 0) {
			if (disk) fclose(disk);
			disk = fopen(FS_FILENAME, "r+b");
			if (!disk) exit(1);
			read_metadata();
			
			if (!login_user("root", "root")) {
				exit(1);
			}
			
			for (int j = 0; j < CONCURRENT_NUM_OPERATIONS; j++) {
				char filename[64];
				snprintf(filename, sizeof(filename), "concurrent_mixed_%d_%d", i, j);
				
				if (j % 3 == 0) {
					FSHandle f = fs_open(filename, CREATE | WRITE);
					if (f.open) {
						char data[32];
						snprintf(data, sizeof(data), "Data %d", j);
						fs_write(&f, 0, strlen(data), (uint8_t*)data);
						fs_close(&f);
					}
				} else if (j % 3 == 1) {
					FSHandle f = fs_open(filename, WRITE);
					if (f.open) {
						char update[32];
						snprintf(update, sizeof(update), "Updated %d", j);
						fs_write(&f, 0, strlen(update), (uint8_t*)update);
						fs_close(&f);
					}
				} else {
					fs_rm(filename);
				}
				usleep(CONCURRENT_RACE_DELAY_US);
			}
			
			if (disk) fclose(disk);
			exit(0);
		} else if (pids[i] < 0) {
			return TEST_FAILED;
		}
	}
	
	int all_success = 1;
	for (int i = 0; i < CONCURRENT_NUM_PROCESSES; i++) {
		int status;
		if (waitpid(pids[i], &status, 0) <= 0 || WEXITSTATUS(status) != 0) {
			all_success = 0;
		}
	}
	
	if (disk) fclose(disk);
	disk = fopen(FS_FILENAME, "r+b");
	read_metadata();
	
	return all_success ? TEST_PASSED : TEST_FAILED;
}

int main() {
	printf("=== File System Test Suite ===\n\n");
	
	// Initialize filesystem for testing
	disk = fopen(FS_FILENAME, "w+b");
	if (!disk) {
		printf("Failed to create test filesystem\n");
		return 1;
	}
	ftruncate(fileno(disk), 1024*1024);
	
	// Initialize metadata and cwd
	read_metadata();
	cwd_offset = meta.root_dirent_offset;
	if (cwd_offset == 0) {
		printf("Warning: Root dirent not initialized\n");
	}
	
	printf("Running tests...\n\n");
	
	// Run all tests
	test_result("Root user exists", test_root_user_exists());
	test_result("Authentication correct password", test_authentication_correct());
	test_result("Authentication incorrect password", test_authentication_incorrect());
	test_result("User creation", test_useradd());
	test_result("Non-root cannot add users", test_useradd_permission());
	test_result("Group creation", test_groupadd());
	test_result("Add user to group", test_usermod());
	test_result("File creation permissions", test_file_creation_permissions());
	test_result("File ownership", test_file_ownership());
	test_result("chmod command", test_chmod());
	test_result("chown command", test_chown());
	test_result("Permission denied read", test_permission_denied_read());
	test_result("Permission denied write", test_permission_denied_write());
	test_result("Root bypasses permissions", test_root_bypass());
	test_result("User deletion", test_userdel());
	test_result("Cannot delete root", test_cannot_delete_root());
	test_result("getfacl command", test_getfacl());
	test_result("chgrp command", test_chgrp());
	test_result("su command", test_su());
	test_result("File operations with permissions", test_file_operations_permissions());
	test_result("File creation", test_file_creation());
	test_result("File write", test_file_write());
	test_result("File read", test_file_read());
	test_result("File write at position", test_file_write_position());
	test_result("File read at position", test_file_read_position());
	test_result("File expansion on write", test_file_expansion());
	test_result("File deletion", test_file_deletion());
	test_result("File shrink", test_file_shrink());
	test_result("File open without create", test_file_open_no_create());
	test_result("File close", test_file_close());
	test_result("Multiple files", test_multiple_files());
	test_result("File statistics", test_file_statistics());
	test_result("Filesystem statistics", test_fs_statistics());
	test_result("Read beyond file size", test_read_beyond_size());
	test_result("File handle management", test_file_handle_management());
	test_result("Write delete verify", test_write_delete_verify());
	test_result("Multiple write delete operations", test_multiple_write_delete());
	test_result("File chain integrity after delete", test_file_chain_integrity());
	test_result("Large file write and delete", test_large_file_operations());
	test_result("Sequential write delete write", test_sequential_write_delete());
	test_result("Delete and recreate same file", test_delete_recreate());
	test_result("Filesystem consistency check", test_fs_consistency());
	test_result("Free block recovery after delete", test_free_block_recovery());
	test_result("Complex multi-file scenario", test_complex_multifile());
	test_result("End-to-end workflow test", test_e2e_workflow());
	
	printf("\n=== Dirent and Path Tests ===\n");
	test_result("mkdir command", test_mkdir());
	test_result("cd path resolution", test_cd_path_resolution());
	test_result("ls list directory", test_ls_list_directory());
	test_result("cp command", test_cp_command());
	test_result("mv command", test_mv_command());
	test_result("Nested directories", test_nested_directories());
	
	printf("\n=== Concurrent Tests ===\n");
	test_result("Concurrent file creation", test_concurrent_file_creation());
	test_result("Concurrent bitmap operations", test_concurrent_bitmap_operations());
	test_result("Concurrent write operations", test_concurrent_write_operations());
	test_result("Concurrent deletion race", test_concurrent_deletion_race());
	test_result("Concurrent mixed operations", test_concurrent_mixed_operations());
	
	printf("\n=== Test Results ===\n");
	printf("Total tests: %d\n", tests_run);
	printf("Passed: %d\n", tests_passed);
	printf("Failed: %d\n", tests_failed);
	
	if (tests_failed == 0) {
		printf("\nAll tests passed!\n");
		return 0;
	} else {
		printf("\nSome tests failed.\n");
		return 1;
	}
}

