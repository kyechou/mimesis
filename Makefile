#
# Makefile
#

TARGET_BITCODE = driver.bc simplerouter.bc #httpd.bc lb.bc

CC          = /opt/cxx-common/libraries/llvm/bin/clang
CXX         = /opt/cxx-common/libraries/llvm/bin/clang++
LD          = /opt/cxx-common/libraries/llvm/bin/clang++
LLVM_LINK   = /opt/cxx-common/libraries/llvm/bin/llvm-link
LN_S        = ln -s
INSTALL     = /usr/bin/install -c
MKDIR_P     = /usr/bin/mkdir -p
CFLAGS      = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c11
CXXFLAGS    = -g -O0 -Xclang -disable-O0-optnone -Wall -Wextra -Werror -std=c++17
CPPFLAGS    =
LDFLAGS     =
LIBS        =

TARGETS_DIR     = ./targets
MCSEMA_DISASS   = $(shell which mcsema-disass-3)
MCSEMA_LIFT     = $(shell which mcsema-lift-10.0)
IDA_PATH        = /opt/idapro-7.5
IDAT64          = /opt/idapro-7.5/idat64

all: $(TARGET_BITCODE)

driver.bc: driver.c
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
		#--std-defs <file>     Load additional external function definitions from <file>
		#--rebase REBASE       Amount by which to rebase a binary
#	$(MCSEMA_LIFT) \
#		--arch amd64 \
#		--os linux \
#		--explicit_args \
#		--merge_segments \
#		--name_lifted_sections \
#		--cfg $(notdir $<).cfg \
#		--output $@

#run-klee: simplerouter.bc driver.bc
#	sudo klee \
#		--max-solver-time=1s \
#		--simplify-sym-indices \
#		--solver-backend=z3 \
#		--solver-optimize-divides \
#		--use-forked-solver \
#		--use-independent-solver \
#		--use-query-log=solver:kquery \
#		--external-calls=concrete \
#		--suppress-external-warnings \
#		\
#		--libc=none \
#		--search=random-path --search=nurs:covnew \
#		--exit-on-error --exit-on-error-type=Abort --exit-on-error-type=ReportError \
#		--max-depth=100 --max-memory=8000 --max-memory-inhibit=false \
#		--max-time=1h --watchdog \
#		\
#		--write-cov \
#		--write-kqueries \
#		--write-paths \
#		--write-sym-paths \
#		--only-output-states-covering-new \
#		\
#		--link-llvm-lib=driver.bc \
#		simplerouter.bc 3
#		#target.bc 3
#
#		#--use-batching-search --batch-time=5s --batch-instructions=10000 \

clean:
	-@rm -rf *.bc *.cfg *.log

distclean: clean
	-@sudo rm -rf klee-*

.PHONY: all clean distclean
