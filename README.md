# radius-mac
A simple RADIUS server for MAC-authentication.

## Build

```
# standard build
make

# build for mipsel (eg. UniFi EdgeRouter X)
make mipsel
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


## Dynamic VLAN using RADIUS MAC Authentication
See https://anton.lindstrom.io/radius-mac/

