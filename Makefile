MIPSEL_IMAGE=radius-mac-builder-mipsel

radius-mac.mipsel: $(wildcard src/*.c) $(wildcard src/*.h)
	docker build -t $(MIPSEL_IMAGE) -f docker/Dockerfile.mipsel docker
	docker run -v $(shell PWD)/src:/src -w /src $(MIPSEL_IMAGE) \
		make CC=mipsel-linux-gnu-gcc clean radius-mac
	cp src/radius-mac radius-mac.mipsel

