#include "locks.h"

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

int fs_lock_read(void) {
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

void fs_unlock_read(void) {
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

int fs_lock(void) {
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

void fs_unlock(void) {
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
