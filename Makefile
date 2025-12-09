MIPSEL_IMAGE=radius-mac-builder-mipsel
MIPS_IMAGE=radius-mac-builder-mips

all:
	@$(MAKE) -C src

clean:
	$(MAKE) -C src clean

mipsel:
	docker build -t $(MIPSEL_IMAGE) --build-arg BUILD_ARCH=mipsel \
		-f docker/Dockerfile.stretch docker
	docker run --rm -v $(shell pwd)/src:/src -w /src $(MIPSEL_IMAGE) \
		make CC=mipsel-linux-gnu-gcc clean radius-mac

mips:
	docker build -t $(MIPS_IMAGE) --build-arg BUILD_ARCH=mips \
		-f docker/Dockerfile.stretch docker
	docker run --rm -v $(shell pwd)/src:/src -w /src $(MIPS_IMAGE) \
		make CC=mips-linux-gnu-gcc clean radius-mac

debian: clean all
	@$(MAKE) -C debian all

debian-mipsel: mipsel
	@$(MAKE) VERSION_SUFFIX=-v3-e50 ARCH=mipsel -C debian all

debian-mips: mips
	@$(MAKE) VERSION_SUFFIX=-v3-e300 ARCH=mips -C debian all

.PHONY: all clean mipsel mips debian debian-mipsel debian-mips
