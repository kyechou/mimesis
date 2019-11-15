#
# Makefile
#

TARGETS     = httpd #lb

SRCS        = $(shell find ./src -type f | grep -E '\.(c|cpp)$$')
OBJS        = $(notdir $(patsubst %.c,%.o,$(SRCS:%.cpp=%.o)))
VPATH       = $(shell find ./src -type d)

CC          = gcc
CXX         = g++
LD          = g++
LN_S        = ln -s
INSTALL     = /usr/bin/install -c
MKDIR_P     = /usr/bin/mkdir -p
CFLAGS      = -O3 -Wall -Wextra -Werror -std=c11
CXXFLAGS    = -O3 -Wall -Wextra -Werror -std=c++17
CPPFLAGS    =
LDFLAGS     =
LIBS        =

.SUFFIXES:
.SUFFIXES: .c .o
.SUFFIXES: .cpp .o

all: $(TARGETS)

httpd: httpd.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-@rm -rf $(TARGETS) *.o

.PHONY: all clean
