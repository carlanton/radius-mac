# radius-mac OpenWrt Package

This package provides a simple RADIUS server for MAC address based
authentication and dynamic VLAN assignment on OpenWrt.

## Package Information

- **Title:** RADIUS server providing MAC addresss authentication
- **Description:** A simple RADIUS server for MAC address authentication.
- **Dependencies:** `libuci`

## Setup: Preparing the OpenWrt Build Environment

Before you can build this package (or any OpenWrt package), you need a
functional OpenWrt build environment.

1. **Obtain and Prepare the OpenWrt Build System:** If you haven't already,
   clone the OpenWrt source repository and prepare the basic build tools and
   toolchain. For detailed instructions, refer to the official OpenWrt
   documentation:

   - [Using the Buildsystem](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem)
   - [Using the SDK (for pre-compiled toolchains)](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)

   A typical initial setup involves:

   ```bash
   # Clone the OpenWrt repository (choose a specific release or master)
   git clone https://git.openwrt.org/openwrt/openwrt.git
   cd openwrt

   # Update feeds (optional at this stage, but good practice)
   ./scripts/feeds update -a
   ./scripts/feeds install -a

   # Prepare the build system configuration (select target, etc.)
   make menuconfig # Select your target device and save

   # Install build tools and toolchain
   # This can take a significant amount of time and disk space
   make tools/install -j$(nproc)
   make toolchain/install -j$(nproc)
   ```

   Ensure your build environment is correctly set up for your target device
   architecture.

## Building the Package (Feed SDK Method)

This method integrates the package into your OpenWrt SDK or build environment
using the standard feeds mechanism. This is often the recommended way to include
custom or third-party packages.

**Prerequisite:** Ensure you have completed the steps in the "Setup: Preparing
the OpenWrt Build Environment" section.

1. **Configure the Feed:** Edit the `feeds.conf` or `feeds.conf.default` file in
   the root of your OpenWrt SDK/build directory. Add a line to define a new feed
   pointing to the `radius-mac` Git repository.

   For example, to add a feed named `radiusmac_project` that pulls from the
   `main` branch of the repository (the OpenWrt package files for this project
   are located in the `openwrt/radius-mac/` subdirectory within the Git
   repository):

   ```conf
   # In feeds.conf or feeds.conf.default
   src-git radiusmac_project https://github.com/carlanton/radius-mac.git;main
   ```

   - `src-git`: Specifies that the feed source is a Git repository.
   - `radiusmac_project`: This is a local name you choose for this feed. You can
     name it anything descriptive (e.g., `custom_packages`,
     `my_radius_mac_feed`).
   - `https://github.com/carlanton/radius-mac.git`: The URL of the Git
     repository.
   - `;main`: (Optional) Specifies the branch to use. Replace `main` with your
     desired branch name (e.g., `release-0.1`). You can also use a specific
     commit hash prefixed with `^` (e.g., `^abcdef1234567890`). If omitted, it
     usually defaults to the repository's default branch.

   The OpenWrt feeds system will scan the contents of this repository. If your
   package `Makefile` (like `openwrt/radius-mac/Makefile` in this project) is
   located in a subdirectory of the repository, the feeds script will find it
   during the update process.

   **Note on Directory Structure:** The OpenWrt package files (Makefile,
   patches, `files/` directory) are intentionally placed within the
   `openwrt/radius-mac/` subdirectory. When the `scripts/feeds` utility
   processes a feed, it uses the name of the directory containing the package's
   `Makefile` (relative to the feed's root) as the "source package name". By
   using `openwrt/radius-mac/`, the source package name becomes `radius-mac`. If
   the package `Makefile` were located directly in an `openwrt/` directory at
   the root of the feed checkout (e.g., if the feed pointed directly to an
   `openwrt` directory containing the Makefile), the `scripts/feeds install`
   command would incorrectly identify the package as `openwrt`, as was observed
   previously. This nested structure ensures the package is correctly named
   `radius-mac` within the OpenWrt build system.

1. **Update and Install the Package from the Feed:** Run the following commands
   from the root of your OpenWrt SDK/build directory:

   ```bash
   # Update the list of available packages from your new feed
   ./scripts/feeds update radiusmac_project

   # Install the radius-mac package (PKG_NAME from its Makefile) from the feed
   ./scripts/feeds install radius-mac
   ```

   Replace `radiusmac_project` with the feed name you chose in `feeds.conf`. The
   package name `radius-mac` for the `install` command corresponds to the
   `PKG_NAME` defined in the package's `openwrt/radius-mac/Makefile`.

1. **Select the Package in Menuconfig:** Run `make menuconfig`:

   ```bash
   make menuconfig
   ```

   Navigate to `Network` ---> `RADIUS` ---> and select `radius-mac`. It should
   be available and can be marked with `<M>` to build as a module/package or
   `<*>` to build into the firmware. Save your configuration and exit.

1. **Compile the Package:**

   ```bash
   # To compile only this package
   make package/radius-mac/compile V=s

   # Or to build all selected packages (which will include radius-mac if selected)
   # make V=s
   ```

   The compiled `.ipk` package will be located in
   `<sdk_root>/bin/packages/<target_architecture>/<feed_name>/` (e.g.,
   `bin/packages/mipsel_24kc/radiusmac_project/radius-mac_0.1-1_mipsel_24kc.ipk`).

## Building the Package (Manual SDK Method)

**Prerequisite:** Ensure you have completed the steps in the "Setup: Preparing
the OpenWrt Build Environment" section.

1. **Clone or Copy the Package:** Place the OpenWrt package directory
   (`openwrt/radius-mac` from this repository) into the `<sdk_root>/package/`
   directory. It's conventional to name the destination directory in the SDK
   after the package itself, e.g., `radius-mac`.

   Example, assuming your Git repository is cloned at `~/my-radius-mac-repo` and
   your SDK is at `~/openwrt-sdk`:

   ```bash
   # Ensure the target directory in the SDK exists or create it
   # mkdir -p ~/openwrt-sdk/package/radius-mac
   cp -r ~/my-radius-mac-repo/openwrt/radius-mac ~/openwrt-sdk/package/
   ```

   This will result in the package Makefile being at
   `~/openwrt-sdk/package/radius-mac/Makefile`.

1. **Select the Package:** Run `make menuconfig` in the SDK root directory.
   Navigate to `Network` ---> `RADIUS` ---> and select `radius-mac` (it should
   be marked with `<M>` to build as a module/package).

   ```bash
   make menuconfig
   ```

   Save your configuration and exit.

1. **Compile the Package:**

   ```bash
   # To compile only this package
   make package/radius-mac/compile V=s

   # Or to build all selected packages
   # make V=s
   ```

   The compiled `.ipk` package will be located in
   `<sdk_root>/bin/packages/<target_architecture>/base/` (e.g.,
   `bin/packages/mipsel_24kc/base/radius-mac_0.1-1_mipsel_24kc.ipk`).

## Installation on OpenWrt

1. **Transfer the Package:** Copy the generated `radius-mac_...ipk` file to your
   OpenWrt device (e.g., using `scp`).

1. **Install the Package:** Log in to your OpenWrt device via SSH and run:

   ```bash
   opkg update
   opkg install /path/to/radius-mac_...ipk
   ```

## Configuration

Configuration is managed through UCI, with the main configuration file located
at `/etc/config/radius-mac`.

### Configuring with UCI Commands

While you can directly edit `/etc/config/radius-mac`, you can also use the `uci`
command-line utility for a more programmatic approach. For a comprehensive guide
on UCI, see the
[OpenWrt UCI documentation](https://openwrt.org/docs/guide-user/base-system/uci).

Here are some examples for managing the `radius-mac` configuration:

**1. Show current configuration:**

```bash
uci show radius-mac
```

**2. Enable the default server instance:**

```bash
uci set radius-mac.default.enabled='1'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

**3. Change the shared secret for the default server:**

```bash
uci set radius-mac.default.secret='newsupersecretpassword'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

**4. Set the default VLAN ID for the default server:**

```bash
uci set radius-mac.default.default_vlan='10'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

**5. Add a new client device to the 'default' server:**

```bash
# Create a new client section (e.g., named 'newclient')
uci add radius-mac radius-mac-client
uci rename radius-mac.@radius-mac-client[-1]=newclient # Give it a unique name

# Configure the new client
uci set radius-mac.newclient.server='default'
uci set radius-mac.newclient.mac='AA:BB:CC:DD:EE:FF'
uci set radius-mac.newclient.description='New Laptop'
uci set radius-mac.newclient.vlan='25'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

*Note: `radius-mac.@radius-mac-client[-1]` refers to the most recently added
anonymous section of type `radius-mac-client`.*

**6. Modify an existing client's VLAN (e.g., client 'smarttv'):**

```bash
uci set radius-mac.smarttv.vlan='23'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

**7. Delete a client (e.g., client 'toaster'):**

```bash
uci delete radius-mac.toaster
uci commit radius-mac
/etc/init.d/radius-mac reload
```

**8. Create and configure a new server instance (e.g., 'guest_network'):**

```bash
# Add a new server section
uci add radius-mac radius-mac-server
uci rename radius-mac.@radius-mac-server[-1]=guest_network

# Configure the new server instance
uci set radius-mac.guest_network.enabled='1'
uci set radius-mac.guest_network.address='0.0.0.0'
uci set radius-mac.guest_network.port='1813' # Use a different port or IP
uci set radius-mac.guest_network.secret='guestsecret'
uci set radius-mac.guest_network.default_vlan='200'
uci commit radius-mac
/etc/init.d/radius-mac reload
```

Remember to always run `uci commit radius-mac` to save changes to flash and then
reload or restart the service for the changes to take effect.

### Default Configuration File Example

The default configuration file (`openwrt/radius-mac/files/radius-mac.conf`)
provides a template:

```uci
# Server configuration parameters
config radius-mac-server 'default'
	option enabled '0'        # Set to '1' to enable this server instance
	option address '0.0.0.0'  # IP address to listen on
	option port '1812'        # UDP port to listen on
	option secret 'shared-secret-xyz' # RADIUS shared secret
	option default_vlan '1'   # Default VLAN ID if a client has no specific VLAN

# # Client device: SmartTV
# config radius-mac-client 'smarttv'
#	option server 'default'     # Links this client to the 'default' server instance
#	option mac '10:11:12:13:14' # MAC address of the client
#	option description 'SmartTV'  # Optional description
#	option vlan '22'            # VLAN ID to assign to this client
```

### Server Configuration (`config radius-mac-server`)

- `option enabled '1'`: Enables or disables this server instance.
- `option address '0.0.0.0'`: The IP address the RADIUS server will listen on.
  `0.0.0.0` means listen on all available interfaces.
- `option port '1812'`: The UDP port for RADIUS authentication requests.
- `option secret 'your_shared_secret'`: The shared secret between the RADIUS
  server and your NAS (e.g., wireless access point). **Change this to a strong,
  unique secret.**
- `option default_vlan '1'`: (Optional) The VLAN ID assigned to authenticated
  clients if no specific VLAN is configured for their MAC address.

You can define multiple server instances by creating more
`config radius-mac-server 'instance_name'` sections. Each instance will generate
its own `.ini` file (e.g., `/etc/radius-mac-instance_name.ini`) and run as a
separate process. The `default` instance uses `/etc/radius-mac.ini`.

### Client Configuration (`config radius-mac-client`)

For each device you want to authenticate:

- `option server 'default'`: Specifies which server instance this client
  configuration applies to. Match this to the name of your
  `config radius-mac-server` section.
- `option mac 'XX:XX:XX:XX:XX:XX'`: The MAC address of the client device.
- `option description 'My Device'`: An optional description for the client.
- `option vlan '100'`: (Optional) The VLAN ID to be assigned to this client upon
  successful authentication.

### Running Multiple Server Instances and Configuration Validation

The `radius-mac` package supports running multiple distinct RADIUS server
instances simultaneously, each with its own configuration (address, port,
secret, clients, default VLAN).

**Defining Multiple Servers:**

To run multiple instances, define multiple
`config radius-mac-server 'instance_name'` sections in `/etc/config/radius-mac`.
Each instance must have a unique name.

For example, to run two instances, one named `default` and another named `zany`:

```uci
config radius-mac-server 'default'
	option enabled '1' # Note: 'enabled' is the correct option, not 'enable'
	option address '192.168.136.1'
	option port '1812'
	option secret 'maltcalmpressoverdraftbonehead'
	option default_vlan '50'

config radius-mac-server 'zany'
	option enabled '1' # Note: 'enabled' is the correct option, not 'enable'
	option address '192.168.137.1'
	option port '1812' # Can be the same port if on different IPs, or different ports
	option secret 'otherpassword'
	option default_vlan '20'

# Clients for the 'default' server
config radius-mac-client 'berstuk'
	option server 'default'
	option mac 'd8:43:ae:c0:a7:54'
	option vlan '20'
	# ... other clients for 'default' ...

# Clients for the 'zany' server
config radius-mac-client 'toaster'
	option server 'zany'
	option mac '20:81:12:13:44:55'
	option description 'Toaster'
	option vlan '24'
```

**Generated Configuration Files and Processes:**

The init script will generate a separate `.ini` configuration file for each
enabled server instance:

- The instance named `default` will use `/etc/radius-mac.ini`.
- Any other instance named `your_instance_name` will use
  `/etc/radius-mac-your_instance_name.ini`.

Following the example above, you would find:

- `/etc/radius-mac.ini` (for the `default` server)
- `/etc/radius-mac-zany.ini` (for the `zany` server)

Each enabled server instance runs as a separate `radius-mac` process. You can
verify this using `pgrep`:

```bash
root@openwrt:~# pgrep -af radius-mac
5502 /usr/bin/radius-mac -c /etc/radius-mac.ini
5503 /usr/bin/radius-mac -c /etc/radius-mac-zany.ini
```

This shows two `radius-mac` processes, each launched with its respective
configuration file.

**Configuration Validation and Error Handling:**

The init script performs validation on the UCI configuration before generating
the `.ini` files and starting the server instances.

- **Server Configuration:** If a `config radius-mac-server` section has critical
  errors (e.g., missing `address`, `port`, `secret`, or invalid values for
  these), the init script will log an error, and that specific server instance
  will **not** be started. The corresponding `.ini` file might not be generated
  or might be incomplete.
- **Client Configuration:** If a `config radius-mac-client` section has errors
  (e.g., an invalid MAC address format, missing MAC address, or VLAN ID out of
  range), the init script will log an error for that specific client and
  **skip** adding it to the server's `.ini` file. However, the server instance
  itself will still attempt to start with its valid clients (if any) and its
  server-level configuration, provided the server configuration itself is valid.

For example, if a client entry had `option mac 'invalid-mac-format'`, it would
be skipped for its associated server, an error would be logged (viewable with
`logread`), but the server instance could still run and serve other correctly
configured clients.

### Applying Configuration Changes

After modifying `/etc/config/radius-mac`, you can apply the changes by:

1. Reloading the service:
   ```bash
   /etc/init.d/radius-mac reload
   ```
1. Or restarting the service:
   ```bash
   /etc/init.d/radius-mac restart
   ```

## Service Management

The `radius-mac` service is managed by an init script:

- **Start:** `/etc/init.d/radius-mac start`
- **Stop:** `/etc/init.d/radius-mac stop`
- **Restart:** `/etc/init.d/radius-mac restart`
- **Reload:** `/etc/init.d/radius-mac reload` (regenerates .ini files and
  restarts)
- **Enable at boot:** `/etc/init.d/radius-mac enable`
- **Disable at boot:** `/etc/init.d/radius-mac disable`

The init script reads the UCI configuration, generates the necessary `.ini`
file(s) in `/etc/` (e.g., `/etc/radius-mac.ini` for the default server
instance), and then starts the `radius-mac` binary with the appropriate
configuration. Log messages from the init script and the `radius-mac` daemon can
typically be found in the system log (`logread`).

## Further Information

For more details on the underlying `radius-mac` server and its capabilities,
including dynamic VLAN assignment, you might find the original project's
documentation useful:

- [Original radius-mac GitHub](https://github.com/carlanton/radius-mac)
- [Blog post on Dynamic VLAN using RADIUS MAC Authentication](https://anton.lindstrom.io/radius-mac/)
