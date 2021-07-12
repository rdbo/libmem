CC=gcc
CFLAGS=-g -std=c89 -ansi -pedantic -Wall -Wextra
OUT_DIR=./bin
LIBMEM_DIR=./libmem
LIBMEM_SRC=$(LIBMEM_DIR)/libmem.c
LIBMEM_OUT=libmem.so
LIBMEM_CFLAGS=-o $(OUT_DIR)/$(LIBMEM_OUT) -shared -fPIC -DLM_EXPORT -ldl
TESTS_DIR=./tests
TESTS_SRC=$(TESTS_DIR)/tests.c
TESTS_OUT=tests
TESTS_CFLAGS=-o $(OUT_DIR)/$(TESTS_OUT) -I$(LIBMEM_DIR) -DLM_IMPORT -DTARGET_NAME=\"$(TESTS_OUT)\" -Wl,-R,$(OUT_DIR) -Wl,--enable-new-dtags -L$(OUT_DIR) -l:$(LIBMEM_OUT) -ldl

all: setup libmem tests

libmem: setup
	@echo "[+] Building 'libmem'"
	$(CC) $(CFLAGS) $(LIBMEM_CFLAGS) $(LIBMEM_SRC)
	@echo "[-] Done building 'libmem'"

tests: setup
	@echo "[+] Building 'tests'"
	$(CC) $(CFLAGS) $(TESTS_CFLAGS) $(TESTS_SRC)
	@echo "[-] Done building 'tests'"

setup:
	@if [ ! -d $(OUT_DIR) ]; then mkdir $(OUT_DIR); fi

clean:
	@if [ -d $(OUT_DIR) ]; then rm -rf $(OUT_DIR); fi
