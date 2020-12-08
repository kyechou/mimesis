#
# Makefile
#

TARGETS     = simplerouter httpd lb

CC          = /opt/cxx-common/libraries/llvm/bin/clang
CXX         = /opt/cxx-common/libraries/llvm/bin/clang++
LD          = /opt/cxx-common/libraries/llvm/bin/clang++
LLVM_LINK   = /opt/cxx-common/libraries/llvm/bin/llvm-link
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

simplerouter: simplerouter.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

httpd: httpd.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

LB_SRCS = $(shell ls LB* | grep -E '\.(c|cpp)')
LB_OBJS = $(notdir $(patsubst %.c,%.o,$(LB_SRCS:%.cpp=%.o)))

lb: $(LB_OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-@rm -rf $(TARGETS) *.o

.PHONY: all clean
