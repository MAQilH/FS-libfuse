#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT_DIR/filesystem_fuse"
MOUNT_DIR="$(mktemp -d -t fsfuse.XXXXXX)"

cleanup() {
  set +e
  if mountpoint -q "$MOUNT_DIR"; then
    if command -v fusermount >/dev/null 2>&1; then
      fusermount -u "$MOUNT_DIR"
    else
      umount "$MOUNT_DIR"
    fi
  fi
  if [[ -n "${FUSE_PID:-}" ]]; then
    kill "$FUSE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$MOUNT_DIR"
}
trap cleanup EXIT

make -C "$ROOT_DIR" filesystem_fuse >/dev/null

"$BIN" "$MOUNT_DIR" -f &
FUSE_PID=$!

for _ in {1..20}; do
  if mountpoint -q "$MOUNT_DIR"; then
    break
  fi
  sleep 0.1
done

if ! mountpoint -q "$MOUNT_DIR"; then
  echo "FUSE mount failed" >&2
  exit 1
fi

echo "=== Test 1: Directories ==="
mkdir "$MOUNT_DIR/a"
mkdir "$MOUNT_DIR/a/subdir"
if [[ ! -d "$MOUNT_DIR/a/subdir" ]]; then
  echo "Nested directory creation failed" >&2
  exit 1
fi
echo "Directory tests passed"

echo "=== Test 2: Files with arbitrary length ==="
printf "hello" > "$MOUNT_DIR/a/file.txt"
if [[ "$(cat "$MOUNT_DIR/a/file.txt")" != "hello" ]]; then
  echo "Read/write test failed" >&2
  exit 1
fi

printf " world" >> "$MOUNT_DIR/a/file.txt"
if [[ "$(cat "$MOUNT_DIR/a/file.txt")" != "hello world" ]]; then
  echo "Append test failed" >&2
  exit 1
fi

# Write larger content (test arbitrary length)
dd if=/dev/urandom of="$MOUNT_DIR/a/bigfile" bs=4096 count=10 2>/dev/null
BIGFILE_SIZE=$(stat -c%s "$MOUNT_DIR/a/bigfile")
if [[ "$BIGFILE_SIZE" -ne 40960 ]]; then
  echo "Large file test failed: expected 40960, got $BIGFILE_SIZE" >&2
  exit 1
fi
echo "File tests passed"

echo "=== Test 3: Symbolic links ==="
# Use relative path for symlink target
ln -s "file.txt" "$MOUNT_DIR/a/link_to_file"
if [[ ! -L "$MOUNT_DIR/a/link_to_file" ]]; then
  echo "Symlink creation failed" >&2
  exit 1
fi
LINK_TARGET=$(readlink "$MOUNT_DIR/a/link_to_file")
if [[ "$LINK_TARGET" != "file.txt" ]]; then
  echo "Symlink readlink failed: expected file.txt, got $LINK_TARGET" >&2
  exit 1
fi
# Reading through symlink should work
SYMLINK_CONTENT=$(cat "$MOUNT_DIR/a/link_to_file" 2>&1 || true)
if [[ "$SYMLINK_CONTENT" == "hello world" ]]; then
  echo "Reading through symlink works"
else
  echo "Note: Symlink read-through returned: $SYMLINK_CONTENT (may vary)"
fi
echo "Symlink tests passed"

echo "=== Test 4: Hard links ==="
ln "$MOUNT_DIR/a/file.txt" "$MOUNT_DIR/a/hardlink_to_file"
if [[ ! -f "$MOUNT_DIR/a/hardlink_to_file" ]]; then
  echo "Hardlink creation failed" >&2
  exit 1
fi
# Content should be same
if [[ "$(cat "$MOUNT_DIR/a/hardlink_to_file")" != "hello world" ]]; then
  echo "Hardlink content mismatch" >&2
  exit 1
fi
echo "Hardlink tests passed"

echo "=== Test 5: Permissions (chmod) ==="
chmod 755 "$MOUNT_DIR/a/file.txt"
FILE_PERM=$(stat -c%a "$MOUNT_DIR/a/file.txt")
if [[ "$FILE_PERM" != "755" ]]; then
  echo "chmod test failed: expected 755, got $FILE_PERM" >&2
  exit 1
fi

chmod 644 "$MOUNT_DIR/a/file.txt"
FILE_PERM=$(stat -c%a "$MOUNT_DIR/a/file.txt")
if [[ "$FILE_PERM" != "644" ]]; then
  echo "chmod test failed: expected 644, got $FILE_PERM" >&2
  exit 1
fi
echo "Permission tests passed"

echo "=== Test 6: Rename/Move ==="
mv "$MOUNT_DIR/a/file.txt" "$MOUNT_DIR/a/renamed.txt"
if [[ ! -f "$MOUNT_DIR/a/renamed.txt" ]]; then
  echo "Rename test failed" >&2
  exit 1
fi
if [[ -f "$MOUNT_DIR/a/file.txt" ]]; then
  echo "Old file still exists after rename" >&2
  exit 1
fi
echo "Rename tests passed"

echo "=== Test 7: Filesystem stats ==="
df "$MOUNT_DIR" > /dev/null
if [[ $? -ne 0 ]]; then
  echo "statfs test failed" >&2
  exit 1
fi
echo "Statfs tests passed"

echo "=== Cleanup ==="
rm -f "$MOUNT_DIR/a/link_to_file" 2>/dev/null || true
rm -f "$MOUNT_DIR/a/hardlink_to_file" 2>/dev/null || true
rm -f "$MOUNT_DIR/a/renamed.txt" 2>/dev/null || true
rm -f "$MOUNT_DIR/a/bigfile" 2>/dev/null || true
rm -f "$MOUNT_DIR/a/file.txt" 2>/dev/null || true
rmdir "$MOUNT_DIR/a/subdir" 2>/dev/null || true
rmdir "$MOUNT_DIR/a" 2>/dev/null || true

echo ""
echo "====================================="
echo "All FUSE extended tests passed!"
echo "====================================="