TARGETS = \
	target-builder

PUSH_TARGETS = $(TARGETS:%=%-push)

CONTAINERS := $(shell docker ps -a -q)
NON_TAGGED_IMGS := $(shell docker images | grep '<none>' | awk -F ' ' '{print $$3}')
IMAGES := $(shell docker images -q)
S2E_REPO_DIR := $(shell ls -d ../../s2e.* | head -n1)

all: $(TARGETS)

push: $(PUSH_TARGETS)

$(TARGETS):
	cp $(S2E_REPO_DIR)/s2e/images/.tmp-output/linux-4.9.3-x86_64/*.deb ./$@/
	docker build -t kyechou/$@:latest ./$@

$(PUSH_TARGETS):
	docker push kyechou/$(@:%-push=%):latest

clean:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(NON_TAGGED_IMGS)" ] || docker rmi -f $(NON_TAGGED_IMGS)

cleanall:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(IMAGES)" ] || docker rmi -f $(IMAGES)

.PHONY: all push $(TARGETS) $(PUSH_TARGETS) clean cleanall
