CONTAINERS := $(shell docker ps -a -q)
NON_TAGGED_IMGS := $(shell docker images | grep '<none>' | awk -F ' ' '{print $$3}')
IMAGES := $(shell docker images -q)
S2E_REPO_DIR := $(shell realpath ../../s2e)
LINUX_VERSION := 6.8.2

all: mimesis

mimesis: systemtap
	docker tag $<:latest $@:latest

systemtap: s2e \
	linux-headers-$(LINUX_VERSION)-s2e_$(LINUX_VERSION)-1_amd64.deb \
	linux-image-$(LINUX_VERSION)-s2e_$(LINUX_VERSION)-1_amd64.deb \
	linux-image-$(LINUX_VERSION)-s2e-dbg_$(LINUX_VERSION)-1_amd64.deb \
	linux-libc-dev_$(LINUX_VERSION)-1_amd64.deb
	docker build -t $@:latest -f $@.dockerfile .

linux-%.deb:
	cp $(S2E_REPO_DIR)/images/.tmp-output/linux-$(LINUX_VERSION)-x86_64/$@ ./

s2e:
	docker build --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g) \
		-t $@:latest -f $@.dockerfile .

clean:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(NON_TAGGED_IMGS)" ] || docker rmi -f $(NON_TAGGED_IMGS)

cleanall:
	@[ -z "$(CONTAINERS)" ] || docker rm -f $(CONTAINERS)
	@[ -z "$(IMAGES)" ] || docker rmi -f $(IMAGES)

.PHONY: all mimesis systemtap s2e clean cleanall
