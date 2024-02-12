#
# Makefile
#

TARGETS     = lb

LB_SRCS     = $(shell find ./src/lb -type f | grep -E '\.(c|cpp)$$')
LB_OBJS     = $(notdir $(patsubst %.c,%.o,$(LB_SRCS:%.cpp=%.o)))
VPATH       = $(shell find ./src -type d)

CC          = gcc
CXX         = g++
LD          = g++
LN_S        = ln -s
INSTALL     = /usr/bin/install -c
MKDIR_P     = /usr/bin/mkdir -p
CFLAGS      = -O0 -Wall -Wextra -Werror -std=c11
CXXFLAGS    = -O0 -Wall -Wextra -Werror -std=c++17
CPPFLAGS    = -iquote ./src -iquote ./src/lb
LDFLAGS     =
LIBS        =

.SUFFIXES:
.SUFFIXES: .c .o
.SUFFIXES: .cpp .o

all: $(TARGETS)

httpd: httpd.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

lb: $(LB_OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-@rm -rf $(TARGETS) *.o

.PHONY: all clean
