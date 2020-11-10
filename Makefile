#
# Makefile
#

TARGETS     = simplerouter
#TARGETS     = httpd lb simplerouter

LB_SRCS     = $(shell find ./src/lb -type f | grep -E '\.(c|cpp)$$')
LB_OBJS     = $(notdir $(patsubst %.c,%.o,$(LB_SRCS:%.cpp=%.o)))
VPATH       = $(shell find ./src -type d)

CC          = clang
LD          = clang
LN_S        = ln -s
INSTALL     = /usr/bin/install -c
MKDIR_P     = /usr/bin/mkdir -p
CFLAGS      = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c11
CXXFLAGS    = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c++17
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

simplerouter.bc: simplerouter
	retdec-decompiler simplerouter

driver.bc: src/driver.c
	$(CC) $(CFLAGS) -emit-llvm -c $^ -o $@

topdown: src/simplerouter.c
	$(CC) $(CFLAGS) -emit-llvm -c $^ -o simplerouter.bc

run-klee: topdown driver.bc
	sudo klee --libc=uclibc --use-query-log=solver:kquery \
		--external-calls=concrete --solver-optimize-divides \
		--output-dir=klee-out --only-output-states-covering-new \
		--search=nurs:covnew --use-incomplete-merge \
		--exit-on-error-type=Abort --exit-on-error-type=ReportError \
		--watchdog --max-time=1h --max-depth=100 --max-memory=8000 \
		--link-llvm-lib=driver.bc simplerouter.bc

		#--use-batching-search --batch-time=5s --batch-instructions=10000 \

clean:
	-@rm -rf $(TARGETS) *.o *.bc simplerouter*

.PHONY: all clean topdown run-klee
