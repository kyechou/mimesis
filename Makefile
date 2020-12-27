#
# Makefile for getting LLVM IR bitcodes
#

DRIVER_BC   = driver.bc
TARGET_BC   = router-s1.bc topdown-router-s1.bc \
              router-s2.bc topdown-router-s2.bc \
              router-s3.bc topdown-router-s3.bc
BITCODES    = $(DRIVER_BC) $(TARGET_BC) #httpd.bc lb.bc

vcpkg_prefix= /opt/cxx-common/installed/x64-linux-rel
CC          = $(vcpkg_prefix)/bin/clang
CXX         = $(vcpkg_prefix)/bin/clang++
LD          = $(vcpkg_prefix)/bin/clang++
LLVM_LINK   = $(vcpkg_prefix)/bin/llvm-link
LN_S        = ln -s
INSTALL     = /usr/bin/install -c
MKDIR_P     = /usr/bin/mkdir -p
CFLAGS      = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c11
CXXFLAGS    = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c++17
CPPFLAGS    = -iquote .
LDFLAGS     =
LIBS        =
DEPTH_LIMIT ?= 2

TARGETS_DIR     = ./targets
MCSEMA_DISASS   = $(shell which mcsema-disass-3)
MCSEMA_LIFT     = $(shell which mcsema-lift-10.0)
IDA_PATH        = /opt/idapro-7.5
IDAT64          = /opt/idapro-7.5/idat64

all: $(BITCODES)

driver.bc: driver.c
	$(CC) $(CPPFLAGS) -DDEPTH_LIMIT=$(DEPTH_LIMIT) $(CFLAGS) -emit-llvm -c $^ -o $@

topdown-%.bc: $(TARGETS_DIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -emit-llvm -c $^ -o $@

%.bc: $(TARGETS_DIR)/%
	$(MCSEMA_DISASS) \
		--disassembler "$(IDAT64)" \
		--arch amd64 \
		--os linux \
		--entrypoint main \
		$(shell file $< | grep ' pie ' >/dev/null 2>&1 && echo '--pie-mode') \
		--output $(notdir $<).cfg \
		--log_file $(notdir $<).log \
		--binary $<
	$(MCSEMA_LIFT) \
		--arch amd64 \
		--os linux \
		--loglevel 0 \
		--explicit_args \
		--cfg $(notdir $<).cfg \
		--output $@

$(TARGETS_DIR)/%:
	make -C $(TARGETS_DIR) $(notdir $@)

clean:
	-@make -C $(TARGETS_DIR) clean
	-@rm -rf *.bc *.cfg *.log console.txt

distclean: clean
	-@sudo rm -rf klee-last klee-out-*

.PHONY: all clean distclean
