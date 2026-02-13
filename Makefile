CC=gcc
CXX=g++
CFLAGS=-Wall -Wextra -std=c99
MAIN_SRC=main.c
TEST_SRC=test.c
BENCH_SRC=benchmark.c
CONCURRENCY_TEST_SRC=concurrency_test.c
LOCK_WEAKNESS_SRC=lock_weakness_demo.c
MAIN_TARGET=filesystem
TEST_TARGET=test_filesystem
BENCH_TARGET=benchmark
CONCURRENCY_TEST_TARGET=concurrency_test
LOCK_WEAKNESS_TARGET=lock_weakness_demo

# Module source files
MODULE_SRCS=locks.c metadata.c bitmap.c alloc.c users.c permissions.c files.c commands.c

# Profiling flags
PROFILE_CFLAGS=-Wall -Wextra -std=c99 -g -O2 -fno-omit-frame-pointer
DEBUG_CFLAGS=-Wall -Wextra -std=c99 -g -O0

# Tracy configuration
TRACY_DIR=tracy_lib/public
TRACY_CFLAGS=-DTRACY_ENABLE -I$(TRACY_DIR)/..
TRACY_CXXFLAGS=-std=c++17 -DTRACY_ENABLE -I$(TRACY_DIR)/..
TRACY_CLIENT=$(TRACY_DIR)/TracyClient.cpp
# macOS specific flags for Tracy
TRACY_LDFLAGS=-framework Cocoa -lpthread

all: $(MAIN_TARGET)

$(MAIN_TARGET): $(MAIN_SRC) $(MODULE_SRCS)
	$(CC) $(CFLAGS) -lpthread -o $(MAIN_TARGET) $(MAIN_SRC) $(MODULE_SRCS)

# Build with debug symbols for profiling
profile: $(MAIN_SRC) $(MODULE_SRCS)
	$(CC) $(PROFILE_CFLAGS) -lpthread -o $(MAIN_TARGET)_profile $(MAIN_SRC) $(MODULE_SRCS)

# Build benchmark for profiling (non-interactive stress test)
benchmark: $(MAIN_SRC) $(BENCH_SRC) $(MODULE_SRCS)
	$(CC) $(PROFILE_CFLAGS) -c $(MAIN_SRC) -o main_bench.o -DEXCLUDE_MAIN
	$(CC) $(PROFILE_CFLAGS) -lpthread -o $(BENCH_TARGET) main_bench.o $(BENCH_SRC) $(MODULE_SRCS)
	rm -f main_bench.o

# Build with simple text-based profiler (shows bottleneck analysis)
benchmark_profile: $(MAIN_SRC) $(BENCH_SRC) $(MODULE_SRCS) simple_profiler.h
	$(CC) $(PROFILE_CFLAGS) -DENABLE_PROFILING -c $(MAIN_SRC) -o main_prof.o -DEXCLUDE_MAIN
	$(CC) $(PROFILE_CFLAGS) -DENABLE_PROFILING -lpthread -o $(BENCH_TARGET)_profile main_prof.o $(BENCH_SRC) $(MODULE_SRCS)
	rm -f main_prof.o
	@echo ""
	@echo "✅ Built benchmark_profile with bottleneck analysis!"
	@echo "   Run: ./benchmark_profile"
	@echo ""

# ============================================================================
# main2.c benchmarks
# ============================================================================

# Build benchmark2 for main2.c with profiling
benchmark2_profile: main2.c benchmark2.c simple_profiler.h
	$(CC) $(PROFILE_CFLAGS) -DENABLE_PROFILING -c main2.c -o main2_prof.o -DEXCLUDE_MAIN
	$(CC) $(PROFILE_CFLAGS) -DENABLE_PROFILING -o benchmark2_profile main2_prof.o benchmark2.c
	rm -f main2_prof.o
	@echo ""
	@echo "✅ Built benchmark2_profile with bottleneck analysis for main2.c!"
	@echo "   Run: ./benchmark2_profile"
	@echo ""

# Build main2 standalone
filesystem2: main2.c
	$(CC) $(CFLAGS) -o filesystem2 main2.c

# ============================================================================
# Tracy profiler support
# ============================================================================

# Build Tracy client library
tracy_client.o: $(TRACY_CLIENT)
	$(CXX) $(TRACY_CXXFLAGS) -c $(TRACY_CLIENT) -o tracy_client.o

# Build with Tracy profiler support
tracy: $(MAIN_SRC) $(BENCH_SRC) $(MODULE_SRCS) tracy_client.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c $(MAIN_SRC) -o main_tracy.o -DEXCLUDE_MAIN
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c $(BENCH_SRC) -o bench_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c locks.c -o locks_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c metadata.c -o metadata_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c bitmap.c -o bitmap_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c alloc.c -o alloc_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c users.c -o users_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c permissions.c -o permissions_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c files.c -o files_tracy.o
	$(CC) $(PROFILE_CFLAGS) $(TRACY_CFLAGS) -c commands.c -o commands_tracy.o
	$(CXX) -o $(BENCH_TARGET)_tracy main_tracy.o bench_tracy.o locks_tracy.o metadata_tracy.o bitmap_tracy.o alloc_tracy.o users_tracy.o permissions_tracy.o files_tracy.o commands_tracy.o tracy_client.o $(TRACY_LDFLAGS)
	rm -f main_tracy.o bench_tracy.o *_tracy.o

test: $(TEST_TARGET)

# For testing, we compile main.c as object file excluding main(), then link with test.c
$(TEST_TARGET): $(MAIN_SRC) $(TEST_SRC) $(MODULE_SRCS)
	$(CC) $(CFLAGS) -c $(MAIN_SRC) -o main_test.o -DEXCLUDE_MAIN
	$(CC) $(CFLAGS) -lpthread -o $(TEST_TARGET) main_test.o $(TEST_SRC) $(MODULE_SRCS)
	rm -f main_test.o

# Build concurrency test (demonstrates race conditions without locks)
$(CONCURRENCY_TEST_TARGET): $(MAIN_SRC) $(CONCURRENCY_TEST_SRC) $(MODULE_SRCS)
	$(CC) $(CFLAGS) -c $(MAIN_SRC) -o main_concurrency.o -DEXCLUDE_MAIN
	$(CC) $(CFLAGS) -lpthread -o $(CONCURRENCY_TEST_TARGET) main_concurrency.o $(CONCURRENCY_TEST_SRC) $(MODULE_SRCS)
	@rm -f main_concurrency.o

# Build lock weakness demo (demonstrates lock problems)
$(LOCK_WEAKNESS_TARGET): $(MAIN_SRC) $(LOCK_WEAKNESS_SRC) $(MODULE_SRCS)
	$(CC) $(CFLAGS) -lpthread -c $(MAIN_SRC) -o main_lock_demo.o -DEXCLUDE_MAIN
	$(CC) $(CFLAGS) -lpthread -o $(LOCK_WEAKNESS_TARGET) main_lock_demo.o $(LOCK_WEAKNESS_SRC) $(MODULE_SRCS)
	rm -f main_lock_demo.o

clean:
	rm -f $(MAIN_TARGET) $(TEST_TARGET) $(BENCH_TARGET) filesys.db test_filesys.db main_test.o main_bench.o main_prof.o
	rm -f $(MAIN_TARGET)_profile $(BENCH_TARGET)_tracy $(BENCH_TARGET)_profile main_tracy.o bench_tracy.o tracy_client.o
	rm -f filesystem2 benchmark2_profile main2_prof.o
	rm -f $(CONCURRENCY_TEST_TARGET) $(LOCK_WEAKNESS_TARGET) main_concurrency.o main_lock_demo.o
	rm -f perf.data perf.data.old flamegraph.svg

.PHONY: all test clean profile benchmark benchmark_profile benchmark2_profile filesystem2 tracy concurrency_test lock_weakness_demo

