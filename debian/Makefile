# Makefile for building a Debian package

PACKAGE_NAME := raduis-mac
VERSION := 1.0
ARCH := amd64
MAINTAINER := "Anton Lindström"
DESCRIPTION := "Dynamic VLAN using RADIUS MAC Authentication"
SOURCE_DIR := ../src
EXECUTABLE := radius-mac
DEBIAN_DIR := debpkg
VERSION_SUFFIX =

.PHONY: all clean build package

all: clean package

clean:
	@echo "Cleaning up..."
	rm -rf $(DEBIAN_DIR)

package:
	@echo "Creating Debian package..."

	# Set up directory structure and control files
	mkdir -p $(DEBIAN_DIR)/DEBIAN
	@echo "Package: $(PACKAGE_NAME)" > $(DEBIAN_DIR)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(DEBIAN_DIR)/DEBIAN/control
	@echo "Architecture: $(ARCH)" >> $(DEBIAN_DIR)/DEBIAN/control
	@echo "Maintainer: $(MAINTAINER)" >> $(DEBIAN_DIR)/DEBIAN/control
	@echo "Description: $(DESCRIPTION)" >> $(DEBIAN_DIR)/DEBIAN/control
	[ -f postinst ] && cp postinst $(DEBIAN_DIR)/DEBIAN/ && \
		chmod 755 $(DEBIAN_DIR)/DEBIAN/postinst || true
	
	# Copy files to package structure
	mkdir -p $(DEBIAN_DIR)/usr/bin
	cp $(SOURCE_DIR)/$(EXECUTABLE) $(DEBIAN_DIR)/usr/bin/
	cp -r ../opt $(DEBIAN_DIR)	
	dpkg-deb --build $(DEBIAN_DIR) $(PACKAGE_NAME)_$(VERSION)$(VERSION_SUFFIX)_$(ARCH).deb
	@echo "Package created: $(shell pwd)/$(PACKAGE_NAME)_$(VERSION)$(VERSION_SUFFIX)_$(ARCH).deb"

