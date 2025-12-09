# radius-mac
A simple RADIUS server for MAC-authentication.

## Build

```
# standard build
make

# build for mipsel (eg. Ubiquiti EdgeRouter X)
make mipsel

# build for mips (eg. Ubiquiti EdgeRouter 4 or 6P)
make mips
```

## Install
```
cp src/radius-mac /usr/bin

# add systemd service
cp config.ini /etc/radius-mac.ini
cp radius-mac.service /etc/system/systemd/
systemctl daemon-reload
systemctl start radius-mac.service

# enable at boot
systemctl enable radius-mac.service
```
## Build Debian Package

```
# package for host architecture
make debian

# package for mipsel (eg. Ubiquiti EdgeRouter X)
make debian-mipsel

# package for mips (eg. Ubiquiti EdgeRouter 4 or 6P)
make debian-mips

# installing the package
sudo dpkg -i raduis-mac_<version>_<arch>.deb
```

## Dynamic VLAN using RADIUS MAC Authentication
See https://anton.lindstrom.io/radius-mac/

