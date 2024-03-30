TARGETS = \
	s2e \
	systemtap

CONTAINERS := $(shell docker ps -a -q)
NON_TAGGED_IMGS := $(shell docker images | grep '<none>' | awk -F ' ' '{print $$3}')
IMAGES := $(shell docker images -q)
S2E_REPO_DIR := $(shell realpath ../../s2e)

all: $(TARGETS)

s2e:
	docker build --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g) -t $@:latest ./$@

systemtap:
	cp $(S2E_REPO_DIR)/s2e/images/.tmp-output/linux-4.9.3-x86_64/*.deb ./$@/
	docker build -t $@:latest ./$@

clean:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(NON_TAGGED_IMGS)" ] || docker rmi -f $(NON_TAGGED_IMGS)

cleanall:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(IMAGES)" ] || docker rmi -f $(IMAGES)

.PHONY: all push $(TARGETS) clean cleanall
