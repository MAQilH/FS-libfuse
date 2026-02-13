# File System Implementation (FS-libfuse)

A custom filesystem implementation built for educational purposes, featuring user management, permissions, file operations, and concurrent access support.

## Project Structure

```
FS-libfuse/
├── main.c                 # Main entry point with interactive shell
├── test.c                 # Comprehensive test suite
├── stress_test.c          # Stress testing functionality
│
├── Core Modules:
├── metadata.c/h           # Filesystem metadata management
├── bitmap.c/h             # Block allocation bitmap
├── alloc.c/h              # Memory/block allocation
├── locks.c/h              # Concurrency control (mutexes, file locks)
│
├── File System Operations:
├── files.c/h              # File create, read, write, delete operations
├── stats.c/h              # Filesystem statistics
│
├── User & Permission System:
├── users.c/h              # User management (login, authentication)
├── permissions.c/h        # Permission checking and ACL
├── user_commands.c/h      # User management commands (useradd, userdel)
├── group_commands.c/h     # Group management commands (groupadd, groupdel)
│
├── Command Interface:
├── commands.h             # Command definitions
├── command_helpers.c/h    # Command parsing and helpers
├── file_commands.c/h      # File operation commands (chmod, chown, etc.)
│
└── types.h                # Common type definitions and constants
```

## Building the Project

### Prerequisites
- GCC compiler
- pthread library (usually included with GCC)
- Standard C library

### Build Commands

**Build main filesystem executable:**
```bash
make
# or explicitly:
make filesystem
```

**Build test suite:**
```bash
make test
# Creates: test_filesystem
```

**Build with debug symbols:**
```bash
make profile
# Creates: filesystem_profile
```

**Build benchmark:**
```bash
make benchmark
# Creates: benchmark
```

**Clean build artifacts:**
```bash
make clean
```

## Running the Project

### Interactive Filesystem Shell

1. **Start the filesystem:**
   ```bash
   ./filesystem
   ```

2. **Login:**
   - Default root user: `root` / `root`
   - You'll be prompted to login on startup

3. **Available Commands:**

   **User Management:**
   - `login <username>` - Login as a user
   - `logout` - Logout current user
   - `whoami` - Show current user
   - `su <username>` - Switch user (root only)
   - `useradd <username>` - Add new user (root only)
   - `userdel <username>` - Delete user (root only)
   - `groupadd <groupname>` - Create group (root only)
   - `groupdel <groupname>` - Delete group (root only)
   - `usermod <user> -aG <group>` - Add user to group (root only)

   **File Operations:**
   - `open <filename> <mode>` - Open file (modes: `c`=create, `w`=write)
   - `close` - Close currently open file
   - `read <position> <bytes>` - Read from open file
   - `write <position> <data>` - Write to open file
   - `rm <filename>` - Delete file
   - `shrink <new_size>` - Shrink open file to specified size

   **Permission Commands:**
   - `chmod <path> <mode>` - Change file permissions (e.g., `rwxrwxrwx`)
   - `chown <path> <user>:<group>` - Change file ownership
   - `chgrp <path> <group>` - Change file group
   - `getfacl <path>` - Display file access control list

   **System Commands:**
   - `get_fs_stats` - Show filesystem statistics
   - `get_file_stat` - Show current file statistics
   - `stressTest` - Run stress test
   - `viz` - Visualize free block list
   - `exit` - Exit filesystem

### Example Session

```bash
$ ./filesystem
File System Ready.
Please login.
Username: root
Password: root
Logged in as root

root@filesystem$ useradd alice
root@filesystem$ groupadd developers
root@filesystem$ usermod alice -aG developers
root@filesystem$ open test.txt cw
Opened file 'test.txt' successfully.
root@filesystem$ write 0 "Hello, World!"
Wrote 13 bytes.
root@filesystem$ read 0 13
Read 13 bytes: Hello, World!
root@filesystem$ close
Closed the currently open file.
root@filesystem$ chmod test.txt rwxrwxrwx
root@filesystem$ get_fs_stats
root@filesystem$ exit
```

## Testing

### Run Test Suite

```bash
make test
./test_filesystem
```

The test suite includes:
- **User & Authentication Tests** (20 tests)
  - Root user initialization
  - Authentication (correct/incorrect passwords)
  - User creation and deletion
  - Permission checks
  - Group management

- **File Operation Tests** (15 tests)
  - File creation, read, write
  - File deletion and shrinking
  - Position-based operations
  - Multiple file handling

- **Permission Tests** (5 tests)
  - chmod, chown, chgrp
  - Permission denied scenarios
  - Root bypass capabilities

- **Integration Tests** (10 tests)
  - Complex multi-file scenarios
  - Filesystem consistency
  - Free block recovery
  - End-to-end workflows

- **Concurrency Tests** (5 tests)
  - Concurrent file creation
  - Concurrent writes
  - Race condition detection
  - Mixed operations

**Expected Output:**
```
=== File System Test Suite ===

Running tests...

[PASS] Root user exists
[PASS] Authentication correct password
[PASS] File creation
...
=== Test Results ===
Total tests: 55
Passed: 55
Failed: 0

All tests passed!
```

### Stress Test

Run stress test from within the filesystem shell:
```bash
root@filesystem$ stressTest
```

Or build and run benchmark:
```bash
make benchmark
./benchmark
```

## Key Features

- **User Management**: Multi-user support with authentication
- **Permission System**: Unix-like permissions (rwx) with ACL support
- **File Operations**: Create, read, write, delete, shrink files
- **Concurrency**: Thread-safe operations with locking mechanisms
- **Block Allocation**: Efficient bitmap-based block allocation
- **Metadata Management**: Persistent filesystem metadata
- **Statistics**: Filesystem and file-level statistics

## Filesystem Format

- **File**: `filesys.db` (default, ~128MB)
- **Block Size**: 4096 bytes
- **Magic Number**: 0xDEADBEEF
- **Structure**: Metadata → Bitmap → Data blocks

## Notes

- The filesystem persists data in `filesys.db` (or `test_filesys.db` for tests)
- Default root user credentials: `root` / `root`
- Only root can create/delete users and groups
- File permissions follow Unix-style (owner/group/others, rwx)
- Supports concurrent access with proper locking

## CI/CD Pipeline

This project includes a GitHub Actions workflow that automatically runs tests on pull requests and pushes to the `master` branch.

### Automated Testing

The CI pipeline (`.github/workflows/ci.yml`) will:
- Run on all pull requests targeting `master`
- Run on all pushes to `master`
- Build the test suite using `make test`
- Execute all tests via `./test_filesystem`
- Fail if any tests fail (preventing merge)

### Setting Up Branch Protection

To ensure that only code with passing tests can be merged to `master`, configure branch protection rules in GitHub:

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Branches**
3. Click **Add rule** or edit the rule for `master`
4. Enable the following settings:
   - ✅ **Require a pull request before merging**
   - ✅ **Require status checks to pass before merging**
   - ✅ Select **CI Tests** (or `test`) from the status checks list
   - ✅ **Require branches to be up to date before merging**
   - ✅ **Do not allow bypassing the above settings** (optional, for admins)

This ensures that:
- All pull requests must have passing tests before they can be merged
- Direct pushes to `master` will also be blocked if tests fail
- The `master` branch always contains code that passes all tests

## Troubleshooting

**Build errors:**
- Ensure GCC and pthread are installed
- Check that all source files are present

**Permission denied errors:**
- Ensure you have write permissions in the directory
- Check file permissions if accessing existing filesystem

**Test failures:**
- Clean and rebuild: `make clean && make test`
- Ensure no other process is using `test_filesys.db`

**CI/CD failures:**
- Check the GitHub Actions tab for detailed error logs
- Ensure all dependencies are properly listed in the workflow file
- Verify that test files are cleaned up properly (check for leftover `test_filesys.db` files)
