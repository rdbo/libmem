CC=cl.exe
CFLAGS=/Z7
OUT_DIR=.\bin
LIBMEM_DIR=.\libmem
LIBMEM_SRC=$(LIBMEM_DIR)\libmem.c
LIBMEM_OUT=libmem.dll
LIBMEM_CFLAGS=/Fo"$(OUT_DIR)\libmem.o" /LD /MD /DLM_EXPORT /link /DLL /IMPLIB:"$(OUT_DIR)\libmem.lib" /OUT:"$(OUT_DIR)\$(LIBMEM_OUT)"
TESTS_DIR=.\tests
TESTS_SRC=$(TESTS_DIR)\tests.c
TESTS_OUT=tests.exe
TESTS_CFLAGS=/Fo"$(OUT_DIR)\tests.o" /I"$(LIBMEM_DIR)" /DLM_IMPORT /D"TARGET_NAME=\"$(TESTS_OUT)\"" /link "$(OUT_DIR)\libmem.lib" /OUT:"$(OUT_DIR)\$(TESTS_OUT)"

all: setup libmem tests

libmem: setup
	@echo [+] Building 'libmem'
	$(CC) $(LIBMEM_SRC) $(CFLAGS) $(LIBMEM_CFLAGS)
	@echo [-] Done building 'libmem'

tests: setup
	@echo [+] Building 'tests'
	$(CC) $(TESTS_SRC) $(CFLAGS) $(TESTS_CFLAGS)
	@echo [-] Done building 'tests'

setup:
	@if not exist "$(OUT_DIR)" (mkdir "$(OUT_DIR)")

clean:
	@if exist "$(OUT_DIR)" (rmdir /Q /S "$(OUT_DIR)")
