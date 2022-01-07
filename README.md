# Network Check Plugin
The Network Check Plugin - `net_check` - is a plugin for the Multipath 
TCP Daemon - [`mptcpd`](https://intel.github.io/mptcpd/) - that blocks 
[mptcp](https://www.rfc-editor.org/rfc/rfc8684.html) through untrusted 
networks. It works by reading trusted networks from a whitelist or 
untrusted networks from a blacklist. It requires a 
[patched version of mptcpd](https://github.com/dulive/mptcpd/tree/patched_version) 
that adds configuration files for plugins, plugin notification of 
existing system network interfaces and control over event flooding to 
plugins.

## Building
To build `net_check` the following dependencies are required:

- Build dependencies
  - C compiler (C99 compliant)
  - [GNU Autoconf](https://www.gnu.org/software/autoconf/)
  - [GNU Automake](https://www.gnu.org/software/automake/)
  - [GNU Libtool](https://www.gnu.org/software/libtool/)
  - [GNU Autoconf Archive](https://www.gnu.org/software/autoconf-archive/)
  - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
  - [Pandoc](https://pandoc.org/) >= 2.2.1 (needed to convert 
  `README.md` contents from the GitHub markdown format content to 
  plain text)
  <!--- [Doxygen](http://www.doxygen.nl/) (only needed to build-->
- Run and build dependencies
  - Linux kernel NetFilter user API headers
  - [Embedded Linux Library](https://git.kernel.org/pub/scm/libs/ell/ell.git) >= v0.30
  - [Library Minimalistic NetLink](https://netfilter.org/projects/libmnl/)
  - [libnftnl](https://netfilter.org/projects/libnftnl/index.html)
  - [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/index.html)
  - [libstuncli](https://github.com/RuiCunhaM/libstuncli)(optional)

### Bootstrapping
Assuming all build dependencies listed above are installed, bootstrapping
`net_check` simply requires to run the [`bootstrap`](bootstrap) script 
in the top-level source directory, _e.g._:

```sh
$ ./bootstrap
```

### Build Steps
These build steps are the same as the ones found in all Autotool enabled 
software packages, _i.e._ running the `configure` followed by the command 
`make`.

```sh
./configure
make
```

If `configure` returns an error about `mptcpd` not being found set the 
the environment variable `PKG_CONFIG_PATH` to `/usr/local/lib/pkgconfig`
and run it again, _e.g._:

```sh
$ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure
```

Optionally if it is desired to use the system `libstuncli`, it can be done
by giving the `--enable-system-libstuncli` option to `configure`, _e.g._:

```sh
#to use system libstuncli
$ ./configure --enable-system-libstuncli
```

### Instalation

__NOTE__: Installing `net_check` requires to be run with `sudo` if the 
`mptcpd` plugin directory is owned by `root`.

Installing `net_check` on any Linux system just requires to run:

```sh
make install
```

## Configuration

The `net_check` plugin can be configured with a configuration file 
`net_check.conf` in the plugin configuration folder (default: 
`/usr/local/etc/mptcpd/plugins.conf.d`). The following gives an 
explanation of the possible options.

```
[core]

# a list of trusted networks, it can contain IPv4 or IPv6 and with or without mask
whitelist=10.0.16.0/20,10.0.3.20,fe80::0/64

# a list of untrusted networks, it can contain IPv4 or IPv6 and with or without mask
blacklist=10.0.24.0/24

# enables the use of STUN to get the public IPv4
use-stun=false

# Stun server to use
stun-server=stun.l.google.com

# Stun server port to connect
stun-port=3478
```

At least, either a whitelist or blacklist have to be defined, and if 
`use-stun` is set to `true` both `stun-server` and `stun-port` have to be
setted.

## Running

For the plugin to work properly it is necessary that both `existing_ifs` 
and `existing_addrs` `notify-flags` are active, _e.g._:

```sh
$ mptcpd --notify-flags=existing_ifs,existing_addrs
```

Since `mptcpd`, by default, loads the plugins in alphabetic order, it can 
happen that there is another plugin with the same priority that would be 
the first to be loaded and receive the event, instead of this plugin.
A workaround to this is to use the `mptcpd` `--load-plugins` option and 
put `net_check` as the first plugin, followed by the others plugins wished
to load, _e.g._:

```sh
$ mptcpd --load-plugins=net_check,addr_adv,misc_plugin --notify-flags=existing_ifs,existing_addrs
```
