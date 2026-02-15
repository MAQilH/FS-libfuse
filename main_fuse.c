#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include <fuse.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "locks.h"
#include "metadata.h"
#include "users.h"
#include "files.h"
#include "alloc.h"
#include "permissions.h"
#include "bitmap.h"

Metadata meta;
FILE *disk = NULL;
FSHandle current_handle = {0};
UserSession session = {0};
uint32_t cwd_offset = 0;

/* Helper: Set session from FUSE context for multiuser support */
static void set_session_from_context(void) {
	struct fuse_context *ctx = fuse_get_context();
	if (ctx) {
		session.current_uid = ctx->uid;
		session.logged_in = 1;
		/* Try to find username for this uid */
		User u;
		if (find_user_by_uid(ctx->uid, &u)) {
			strncpy(session.current_username, u.username, sizeof(session.current_username) - 1);
		} else {
			snprintf(session.current_username, sizeof(session.current_username), "uid%u", ctx->uid);
		}
	}
}

/* Helper: Check access permission for given entry and mode */
static int check_access_permission(FileEntry *entry, int mode) {
	struct fuse_context *ctx = fuse_get_context();
	if (!ctx) return -EACCES;
	
	/* Root can do anything */
	if (ctx->uid == 0) return 0;
	
	uint32_t perm = entry->permission;
	
	int bit_offset;
	if (entry->owner_uid == ctx->uid) {
		bit_offset = 6;
	} else if (user_in_group(ctx->uid, entry->owner_gid)) {
		bit_offset = 3;
	} else {
		bit_offset = 0;
	}
	
	if (mode & R_OK) {
		if (!((perm >> (bit_offset + 2)) & 1)) return -EACCES;
	}
	if (mode & W_OK) {
		if (!((perm >> (bit_offset + 1)) & 1)) return -EACCES;
	}
	if (mode & X_OK) {
		if (!((perm >> bit_offset) & 1)) return -EACCES;
	}
	
	return 0;
}

/* Helper: Find file by path WITHOUT following symlinks (lstat semantics)
 * This is needed for getattr, readlink, etc. where we want info about the link itself
 */
static int find_file_lstat(const char *path, FileEntry *out, uint32_t *offset_out) {
	if (strcmp(path, "/") == 0) {
		if (meta.root_dirent_offset == 0) return 0;
		fseek(disk, meta.root_dirent_offset, SEEK_SET);
		fread(out, sizeof(FileEntry), 1, disk);
		if (offset_out) *offset_out = meta.root_dirent_offset;
		return 1;
	}
	
	if (path[0] != '/') return 0;
	
	/* Start from root */
	uint32_t current_offset = meta.root_dirent_offset;
	FileEntry current;
	fseek(disk, current_offset, SEEK_SET);
	fread(&current, sizeof(FileEntry), 1, disk);
	
	/* Parse path components */
	char path_copy[256];
	strncpy(path_copy, path + 1, 255);  /* Skip leading / */
	path_copy[255] = '\0';
	
	char *saveptr;
	char *token = strtok_r(path_copy, "/", &saveptr);
	char *next_token = NULL;
	
	while (token != NULL) {
		next_token = strtok_r(NULL, "/", &saveptr);
		
		if (!is_dirent(&current)) {
			return 0;  /* Not a directory */
		}
		
		DirentData data;
		if (!read_dirent(current_offset, &data)) {
			return 0;
		}
		
		int found = 0;
		for (uint32_t i = 0; i < data.child_count; i++) {
			FileEntry child;
			fseek(disk, data.children[i], SEEK_SET);
			fread(&child, sizeof(FileEntry), 1, disk);
			
			if (strcmp(child.name, token) == 0) {
				current_offset = data.children[i];
				current = child;
				
				/* Only follow symlinks if this is NOT the last component */
				if (next_token != NULL && (is_symlink(&current) || is_hardlink(&current))) {
					uint32_t resolved_offset;
					FileEntry resolved_entry;
					if (resolve_link(current_offset, meta.root_dirent_offset, &resolved_offset, &resolved_entry, 1)) {
						current_offset = resolved_offset;
						current = resolved_entry;
					} else {
						return 0;
					}
				}
				
				found = 1;
				break;
			}
		}
		
		if (!found) {
			return 0;
		}
		
		token = next_token;
	}
	
	if (out) *out = current;
	if (offset_out) *offset_out = current_offset;
	return 1;
}

static int fs_fuse_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
	set_session_from_context();

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		stbuf->st_uid = 0;
		stbuf->st_gid = 0;
		return 0;
	}

	FileEntry entry;
	uint32_t offset;
	/* Use lstat semantics - don't follow final symlink */
	if (!find_file_lstat(path, &entry, &offset)) {
		return -ENOENT;
	}

	stbuf->st_uid = entry.owner_uid;
	stbuf->st_gid = entry.owner_gid;

	if (is_dirent(&entry)) {
		stbuf->st_mode = S_IFDIR | (entry.permission & 0777);
		stbuf->st_nlink = 2;
	} else if (is_symlink(&entry)) {
		stbuf->st_mode = S_IFLNK | (entry.permission & 0777);
		stbuf->st_nlink = 1;
		stbuf->st_size = entry.size;
	} else if (is_hardlink(&entry)) {
		/* For hardlinks, get info from target */
		LinkData link_data;
		if (read_link_data(offset, &link_data)) {
			FileEntry target;
			fseek(disk, link_data.target_offset, SEEK_SET);
			if (fread(&target, sizeof(FileEntry), 1, disk) == 1) {
				stbuf->st_mode = S_IFREG | (target.permission & 0777);
				stbuf->st_size = target.size;
				stbuf->st_nlink = link_data.ref_count + 1;
				stbuf->st_uid = target.owner_uid;
				stbuf->st_gid = target.owner_gid;
				return 0;
			}
		}
		stbuf->st_mode = S_IFREG | (entry.permission & 0777);
		stbuf->st_nlink = 1;
		stbuf->st_size = entry.size;
	} else {
		stbuf->st_mode = S_IFREG | (entry.permission & 0777);
		stbuf->st_nlink = 1;
		stbuf->st_size = entry.size;
	}

	return 0;
}

static int fs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
				  off_t offset, struct fuse_file_info *fi) {
	(void)offset;
	(void)fi;
	set_session_from_context();

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	uint32_t dir_offset;
	if (strcmp(path, "/") == 0) {
		dir_offset = meta.root_dirent_offset;
	} else {
		FileEntry entry;
		if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &dir_offset)) {
			return -ENOENT;
		}
		if (!is_dirent(&entry)) {
			return -ENOTDIR;
		}
	}

	DirentData dirent;
	if (!read_dirent(dir_offset, &dirent)) {
		return -EIO;
	}

	for (uint32_t i = 0; i < dirent.child_count; i++) {
		uint32_t child_offset = dirent.children[i];
		if (child_offset == 0) {
			continue;
		}
		FileEntry child;
		fseek(disk, child_offset, SEEK_SET);
		if (fread(&child, sizeof(FileEntry), 1, disk) == 1) {
			filler(buf, child.name, NULL, 0);
		}
	}

	return 0;
}

static int fs_fuse_open(const char *path, struct fuse_file_info *fi) {
	(void)fi;
	set_session_from_context();

	FileEntry entry;
	uint32_t offset;
	if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &offset)) {
		return -ENOENT;
	}

	if (is_dirent(&entry)) {
		return -EISDIR;
	}

	/* Check access permissions based on flags */
	int mode = 0;
	if ((fi->flags & O_ACCMODE) == O_RDONLY) mode = R_OK;
	else if ((fi->flags & O_ACCMODE) == O_WRONLY) mode = W_OK;
	else if ((fi->flags & O_ACCMODE) == O_RDWR) mode = R_OK | W_OK;
	
	int ret = check_access_permission(&entry, mode);
	if (ret != 0) return ret;

	return 0;
}

static int fs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
				 struct fuse_file_info *fi) {
	(void)fi;
	set_session_from_context();

	FSHandle handle = fs_open(path, 0, 0);
	if (!handle.open) {
		return -ENOENT;
	}

	int bytes_read = fs_read(&handle, (uint32_t)offset, (uint32_t)size, (uint8_t *)buf, 0);
	fs_close(&handle);
	return bytes_read;
}

static int fs_fuse_write(const char *path, const char *buf, size_t size,
				  off_t offset, struct fuse_file_info *fi) {
	(void)fi;
	set_session_from_context();

	FSHandle handle = fs_open(path, WRITE, 0);
	if (!handle.open) {
		return -ENOENT;
	}

	int bytes_written = fs_write(&handle, (uint32_t)offset, (uint32_t)size, (uint8_t *)buf, 0);
	fs_close(&handle);
	return bytes_written;
}

static int fs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	(void)fi;
	set_session_from_context();

	FSHandle handle = fs_open(path, CREATE | WRITE, 0);
	if (!handle.open) {
		return -EACCES;
	}
	
	/* Set permissions from mode */
	if (mode != 0) {
		handle.entry.permission = mode & 0777;
		update_file_entry(&handle);
	}
	
	fs_close(&handle);
	return 0;
}

static int fs_fuse_unlink(const char *path) {
	set_session_from_context();
	
	FileEntry entry;
	uint32_t offset;
	if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &offset)) {
		return -ENOENT;
	}
	if (is_dirent(&entry)) {
		return -EISDIR;
	}
	
	/* Check write permission on parent directory */
	char parent_path[256];
	strncpy(parent_path, path, 255);
	parent_path[255] = '\0';
	char *last_slash = strrchr(parent_path, '/');
	if (last_slash && last_slash != parent_path) {
		*last_slash = '\0';
	} else {
		strcpy(parent_path, "/");
	}
	
	FileEntry parent_entry;
	uint32_t parent_offset;
	if (find_file_by_path(parent_path, meta.root_dirent_offset, &parent_entry, &parent_offset)) {
		int ret = check_access_permission(&parent_entry, W_OK);
		if (ret != 0) return ret;
	}

	fs_rm(path, 0);
	return 0;
}

static int fs_fuse_rmdir(const char *path) {
	set_session_from_context();
	
	FileEntry entry;
	uint32_t offset;
	uint32_t parent_offset;
	if (!resolve_path(path, meta.root_dirent_offset, &offset, &entry, &parent_offset)) {
		return -ENOENT;
	}
	if (!is_dirent(&entry)) {
		return -ENOTDIR;
	}

	DirentData data;
	if (read_dirent(offset, &data) && data.child_count > 0) {
		return -ENOTEMPTY;
	}

	fs_rm(path, 0);
	return 0;
}

static int fs_fuse_mkdir(const char *path, mode_t mode) {
	set_session_from_context();

	if (strcmp(path, "/") == 0) {
		return -EEXIST;
	}

	FileEntry existing;
	uint32_t existing_offset;
	if (find_file_by_path(path, meta.root_dirent_offset, &existing, &existing_offset)) {
		return -EEXIST;
	}

	const char *last_slash = strrchr(path, '/');
	const char *dir_name = last_slash ? last_slash + 1 : path;
	if (dir_name[0] == '\0') {
		return -EINVAL;
	}

	char parent_path[256];
	uint32_t parent_offset = meta.root_dirent_offset;
	if (last_slash && last_slash != path) {
		size_t len = (size_t)(last_slash - path);
		if (len >= sizeof(parent_path)) {
			return -ENAMETOOLONG;
		}
		memcpy(parent_path, path, len);
		parent_path[len] = '\0';

		FileEntry parent_entry;
		if (!resolve_path(parent_path, meta.root_dirent_offset, &parent_offset, &parent_entry, NULL)) {
			return -ENOENT;
		}
		if (!is_dirent(&parent_entry)) {
			return -ENOTDIR;
		}
		
		/* Check write permission on parent */
		int ret = check_access_permission(&parent_entry, W_OK);
		if (ret != 0) return ret;
	}

	uint32_t new_offset = create_dirent(dir_name, parent_offset);
	if (new_offset == 0) {
		return -ENOSPC;
	}
	
	/* Set permissions from mode */
	if (mode != 0) {
		FileEntry new_entry;
		fseek(disk, new_offset, SEEK_SET);
		if (fread(&new_entry, sizeof(FileEntry), 1, disk) == 1) {
			new_entry.permission = mode & 0777;
			struct fuse_context *ctx = fuse_get_context();
			if (ctx) {
				new_entry.owner_uid = ctx->uid;
				new_entry.owner_gid = ctx->gid;
			}
			fseek(disk, new_offset, SEEK_SET);
			fwrite(&new_entry, sizeof(FileEntry), 1, disk);
			fflush(disk);
		}
	}
	
	return 0;
}

static int fs_fuse_truncate(const char *path, off_t size) {
	set_session_from_context();
	
	FSHandle handle = fs_open(path, WRITE, 0);
	if (!handle.open) {
		return -ENOENT;
	}
	fs_shrink(&handle, (uint32_t)size, 0);
	fs_close(&handle);
	return 0;
}

/* chmod - change file permissions */
static int fs_fuse_chmod(const char *path, mode_t mode) {
	set_session_from_context();
	
	FileEntry entry;
	uint32_t offset;
	if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &offset)) {
		return -ENOENT;
	}
	
	/* Only owner or root can chmod */
	struct fuse_context *ctx = fuse_get_context();
	if (ctx && ctx->uid != 0 && ctx->uid != entry.owner_uid) {
		return -EPERM;
	}
	
	entry.permission = mode & 0777;
	fseek(disk, offset, SEEK_SET);
	fwrite(&entry, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	return 0;
}

/* chown - change file ownership */
static int fs_fuse_chown(const char *path, uid_t uid, gid_t gid) {
	set_session_from_context();
	
	FileEntry entry;
	uint32_t offset;
	if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &offset)) {
		return -ENOENT;
	}
	
	/* Only root can chown */
	struct fuse_context *ctx = fuse_get_context();
	if (ctx && ctx->uid != 0) {
		/* Non-root can only change group if they own the file and are member of target group */
		if (uid != (uid_t)-1 && uid != entry.owner_uid) {
			return -EPERM;
		}
		if (gid != (gid_t)-1 && !user_in_group(ctx->uid, gid)) {
			return -EPERM;
		}
	}
	
	if (uid != (uid_t)-1) {
		entry.owner_uid = uid;
	}
	if (gid != (gid_t)-1) {
		entry.owner_gid = gid;
	}
	
	fseek(disk, offset, SEEK_SET);
	fwrite(&entry, sizeof(FileEntry), 1, disk);
	fflush(disk);
	
	return 0;
}

/* symlink - create a symbolic link */
static int fs_fuse_symlink(const char *target, const char *linkpath) {
	set_session_from_context();
	
	/* Check if linkpath already exists */
	FileEntry existing;
	uint32_t existing_offset;
	if (find_file_by_path(linkpath, meta.root_dirent_offset, &existing, &existing_offset)) {
		return -EEXIST;
	}
	
	/* Get parent directory */
	const char *last_slash = strrchr(linkpath, '/');
	const char *linkname = last_slash ? last_slash + 1 : linkpath;
	if (linkname[0] == '\0') {
		return -EINVAL;
	}
	
	char parent_path[256];
	uint32_t parent_offset = meta.root_dirent_offset;
	if (last_slash && last_slash != linkpath) {
		size_t len = (size_t)(last_slash - linkpath);
		if (len >= sizeof(parent_path)) {
			return -ENAMETOOLONG;
		}
		memcpy(parent_path, linkpath, len);
		parent_path[len] = '\0';
		
		FileEntry parent_entry;
		if (!resolve_path(parent_path, meta.root_dirent_offset, &parent_offset, &parent_entry, NULL)) {
			return -ENOENT;
		}
		if (!is_dirent(&parent_entry)) {
			return -ENOTDIR;
		}
	}
	
	uint32_t link_offset = create_symlink(linkname, target, parent_offset);
	return link_offset ? 0 : -ENOSPC;
}

/* link - create a hard link */
static int fs_fuse_link(const char *oldpath, const char *newpath) {
	set_session_from_context();
	
	/* Find target file */
	FileEntry target_entry;
	uint32_t target_offset;
	if (!find_file_by_path(oldpath, meta.root_dirent_offset, &target_entry, &target_offset)) {
		return -ENOENT;
	}
	
	/* Cannot hardlink directories */
	if (is_dirent(&target_entry)) {
		return -EPERM;
	}
	
	/* Check if newpath already exists */
	FileEntry existing;
	uint32_t existing_offset;
	if (find_file_by_path(newpath, meta.root_dirent_offset, &existing, &existing_offset)) {
		return -EEXIST;
	}
	
	/* Get parent directory for new link */
	const char *last_slash = strrchr(newpath, '/');
	const char *linkname = last_slash ? last_slash + 1 : newpath;
	if (linkname[0] == '\0') {
		return -EINVAL;
	}
	
	char parent_path[256];
	uint32_t parent_offset = meta.root_dirent_offset;
	if (last_slash && last_slash != newpath) {
		size_t len = (size_t)(last_slash - newpath);
		if (len >= sizeof(parent_path)) {
			return -ENAMETOOLONG;
		}
		memcpy(parent_path, newpath, len);
		parent_path[len] = '\0';
		
		FileEntry parent_entry;
		if (!resolve_path(parent_path, meta.root_dirent_offset, &parent_offset, &parent_entry, NULL)) {
			return -ENOENT;
		}
		if (!is_dirent(&parent_entry)) {
			return -ENOTDIR;
		}
	}
	
	uint32_t link_offset = create_hardlink(linkname, target_offset, parent_offset);
	return link_offset ? 0 : -ENOSPC;
}

/* readlink - read the target of a symbolic link */
static int fs_fuse_readlink(const char *path, char *buf, size_t size) {
	set_session_from_context();
	
	FileEntry entry;
	uint32_t offset;
	/* Use lstat semantics - get the link itself, not the target */
	if (!find_file_lstat(path, &entry, &offset)) {
		return -ENOENT;
	}
	
	if (!is_symlink(&entry)) {
		return -EINVAL;
	}
	
	LinkData link_data;
	if (!read_link_data(offset, &link_data)) {
		return -EIO;
	}
	
	strncpy(buf, link_data.target_path, size - 1);
	buf[size - 1] = '\0';
	
	return 0;
}

/* access - check file access permissions */
static int fs_fuse_access(const char *path, int mode) {
	set_session_from_context();
	
	if (strcmp(path, "/") == 0) {
		return 0;
	}
	
	FileEntry entry;
	uint32_t offset;
	if (!find_file_by_path(path, meta.root_dirent_offset, &entry, &offset)) {
		return -ENOENT;
	}
	
	if (mode == F_OK) {
		return 0;
	}
	
	return check_access_permission(&entry, mode);
}

/* rename - rename/move a file or directory */
static int fs_fuse_rename(const char *oldpath, const char *newpath) {
	set_session_from_context();
	
	int result = fs_mv(oldpath, newpath, meta.root_dirent_offset, 0);
	return result ? 0 : -ENOENT;
}

/* statfs - get filesystem statistics (includes freelist/bitmap info) */
static int fs_fuse_statfs(const char *path, struct statvfs *stbuf) {
	(void)path;
	
	memset(stbuf, 0, sizeof(struct statvfs));
	
	stbuf->f_bsize = BLOCK_SIZE;
	stbuf->f_frsize = BLOCK_SIZE;
	stbuf->f_blocks = TOTAL_BLOCKS;
	
	/* Count free blocks using bitmap */
	uint32_t free_blocks = 0;
	for (uint32_t i = DATA_START_BLOCK; i < TOTAL_BLOCKS; i++) {
		if (is_block_free(i * BLOCK_SIZE)) {
			free_blocks++;
		}
	}
	
	stbuf->f_bfree = free_blocks;
	stbuf->f_bavail = free_blocks;
	stbuf->f_files = 0;  /* We don't track inode count */
	stbuf->f_ffree = 0;
	stbuf->f_namemax = 31;  /* Max filename length from FileEntry.name */
	
	return 0;
}

/* utimens - set file timestamps (no-op since we don't track timestamps) */
static int fs_fuse_utimens(const char *path, const struct timespec tv[2]) {
	(void)path;
	(void)tv;
	/* We don't track timestamps, but return success */
	return 0;
}

static struct fuse_operations fs_fuse_oper = {
	.getattr  = fs_fuse_getattr,
	.readdir  = fs_fuse_readdir,
	.open     = fs_fuse_open,
	.read     = fs_fuse_read,
	.write    = fs_fuse_write,
	.create   = fs_fuse_create,
	.unlink   = fs_fuse_unlink,
	.mkdir    = fs_fuse_mkdir,
	.rmdir    = fs_fuse_rmdir,
	.truncate = fs_fuse_truncate,
	.chmod    = fs_fuse_chmod,
	.chown    = fs_fuse_chown,
	.symlink  = fs_fuse_symlink,
	.link     = fs_fuse_link,
	.readlink = fs_fuse_readlink,
	.access   = fs_fuse_access,
	.rename   = fs_fuse_rename,
	.statfs   = fs_fuse_statfs,
	.utimens  = fs_fuse_utimens,
};

int main(int argc, char *argv[]) {
	disk = fopen(FS_FILENAME, "r+b");
	if (!disk) {
		disk = fopen(FS_FILENAME, "w+b");
		ftruncate(fileno(disk), FS_SIZE);
	}

	read_metadata();
	initialize_root_user();

	cwd_offset = meta.root_dirent_offset;
	if (cwd_offset == 0) {
		printf("Warning: Root dirent not initialized. Some operations may fail.\n");
	}

	session.logged_in = 1;
	session.current_uid = 0;
	strncpy(session.current_username, "root", sizeof(session.current_username) - 1);

	return fuse_main(argc, argv, &fs_fuse_oper, NULL);
}
