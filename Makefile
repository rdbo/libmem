CC=gcc
CFLAGS=-g -std=c89 -ansi -pedantic -Wall -Wextra
LIBMEM_DIR=./libmem
LIBMEM_SRC=$(LIBMEM_DIR)/libmem.c
LIBMEM_OUT=libmem.so
LIBMEM32_OUT=libmem32.so
TESTS_DIR=./tests
TESTS_SRC=./tests/tests.c
TESTS_OUT=tests.o
TESTS32_OUT=tests32.o
OUT_DIR=./bin
LDFLAGS=-Wl,-R,$(OUT_DIR) -Wl,--enable-new-dtags -L$(OUT_DIR) -l:$(LIBMEM_OUT)
LDFLAGS32=-Wl,-R,$(OUT_DIR) -Wl,--enable-new-dtags -L$(OUT_DIR) -l:$(LIBMEM32_OUT)

all: setup libmem libmem32 tests tests32

libmem: setup
	@printf "[+] Building 'libmem'...\n"
	$(CC) -o $(OUT_DIR)/$(LIBMEM_OUT) $(CFLAGS) -shared -fPIC $(LIBMEM_SRC)
	@printf "[-] Done\n"

libmem32: setup
	@printf "[+] Building 'libmem32'...\n"
	$(CC) -o $(OUT_DIR)/$(LIBMEM32_OUT) $(CFLAGS) -m32 -shared -fPIC $(LIBMEM_SRC)
	@printf "[-] Done\n"

tests: libmem setup
	@printf "[+] Building 'tests'...\n"
	$(CC) -o $(OUT_DIR)/$(TESTS_OUT) $(CFLAGS) -I$(LIBMEM_DIR) $(LDFLAGS) $(TESTS_SRC)
	@printf "[-] Done\n"

tests32: libmem32
	@printf "[+] Building 'tests32'...\n"
	$(CC) -o $(OUT_DIR)/$(TESTS32_OUT) $(CFLAGS) -m32 -I$(LIBMEM_DIR) $(LDFLAGS32) $(TESTS_SRC)
	@printf "[-] Done\n"

setup:
	@if [ ! -d $(OUT_DIR) ]; then mkdir $(OUT_DIR); fi

clean:
	@if [ -d $(OUT_DIR) ]; then rm -rf $(OUT_DIR); fi