MIPSEL_IMAGE=radius-mac-builder-mipsel

all:
	@$(MAKE) -C src

clean:
	$(MAKE) -C src clean

mipsel:
	docker build -t $(MIPSEL_IMAGE) -f docker/Dockerfile.mipsel docker
	docker run -v $(shell PWD)/src:/src -w /src $(MIPSEL_IMAGE) \
		make CC=mipsel-linux-gnu-gcc clean radius-mac

.PHONY: all clean mipsel
