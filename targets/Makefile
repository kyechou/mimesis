#
# Makefile for building target application binaries
#

TARGETS     = httpd lb router-s1 router-s2 router-s3

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
CPPFLAGS    = -iquote ..
LDFLAGS     =
LIBS        =

.SUFFIXES:
.SUFFIXES: .c .o
.SUFFIXES: .cpp .o

all: $(TARGETS)

LB_SRCS = $(shell ls LB* | grep -E '\.(c|cpp)')
LB_OBJS = $(notdir $(patsubst %.c,%.o,$(LB_SRCS:%.cpp=%.o)))

lb: $(LB_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-@rm -rf $(TARGETS) *.o

.PHONY: all clean
