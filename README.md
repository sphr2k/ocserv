# About

This program is openconnect VPN server (ocserv), a server for the
[openconnect VPN client](http://www.infradead.org/openconnect/).
It follows the [openconnect protocol](https://gitlab.com/openconnect/protocol)
and is believed to be compatible with CISCO's AnyConnect SSL VPN.

The program consists of:
 1. ocserv, the main server application
 2. occtl, the server's control tool. A tool which allows one to query the
   server for information.
 3. ocpasswd, a tool to administer simple password files.


# Supported platforms

The OpenConnect VPN server is designed and tested to work, with both IPv6
and IPv4, on Linux systems. It is, however, known to work on FreeBSD,
OpenBSD and other BSD derived systems.

Known limitation is that on platforms, which do not support procfs(5),
changes to the configuration must only be made while ocserv(8) is stopped.
Not doing so will cause new worker processes picking up the new
configuration while ocserv-main will use the previous configuration.


# Build dependencies

Required dependencies (Debian pkg/Fedora pkg):
```
libgnutls28-dev      / gnutls-devel
libev-dev            / libev-devel
```

Optional dependencies that enable specific functionality:
```
TCP wrappers: libwrap0-dev       / tcp_wrappers-devel
PAM:          libpam0g-dev       / pam-devel
LZ4:          liblz4-dev         / lz4-devel
seccomp:      libseccomp-dev     / libseccomp-devel
occtl:        libreadline-dev    / readline-devel
              libnl-route-3-dev  / libnl3-devel
GSSAPI:       libkrb5-dev        / krb5-devel
Radius:       libradcli-dev      / radcli-devel
SAML2:        liblasso3-dev      / lasso3-devel
              libglib2.0-dev     / glib2.0-devel
              libapr1-dev        / apr1-devel
```

Dependencies for development, testing, or dependencies that can be skipped
in an embedded system (e.g., because a replacement library is included):

```
libprotobuf-c-dev  / protobuf-c-devel
libtalloc-dev      / libtalloc-devel
libhttp-parser-dev / http-parser-devel
protobuf-c-compiler/ protobuf-c
gperf              / gperf
nuttcp             / nuttcp
lcov               / lcov
libuid-wrapper     / uid_wrapper
libpam-wrapper     / pam_wrapper
libnss-wrapper     / nss_wrapper
libsocket-wrapper  / socket_wrapper
gss-ntlmssp        / gssntlmssp
haproxy            / haproxy
iputils-ping       / iputils
freeradius	   / freeradius
gawk		   / gawk
gnutls-bin	   / gnutls-utils
iproute2	   / iproute
yajl-tools	   / yajl
iproute2	   / iproute
tcpdump      / tcpdump
```

See [README-radius](doc/README-radius.md) for more information on Radius
dependencies and its configuration.

# Build instructions

To build from a distributed release use:

```
$ ./configure && make && make check
```

To test the code coverage of the test suite use the following:
```
$ ./configure --enable-code-coverage
$ make && make check && make code-coverage-capture
```

Note that the code coverage reported does not currently include tests which
are run within docker.

In addition to the prerequisites listed above, building from git requires
the following packages: autoconf, automake, and xz.

To build from the git repository use:
```
$ autoreconf -fvi
$ ./configure && make
```


# Basic installation instructions

Now you need to generate a certificate. E.g.
```
$ certtool --generate-privkey > ./test-key.pem
$ certtool --generate-self-signed --load-privkey test-key.pem --outfile test-cert.pem
```
(make sure you enable encryption or signing)


Create a dedicated user and group for the server unprivileged processes
(e.g., 'ocserv'), and then edit the [sample.config](doc/sample.config)
and set these users on run-as-user and run-as-group options. The run:
```
# cd doc && ../src/ocserv -f -c sample.config
```

# Configuration

Several configuration instruction are available in [the recipes repository](https://gitlab.com/openconnect/recipes).

OIDC and SAML auth instructions are in ./doc

# Profiling

If you use ocserv on a server with significant load and you'd like to help
improve it, you may help by sending profiling information. That includes
the bottlenecks in software, so future optimizations could be spent on the
real needs.

In a Linux system you can profile ocserv using the following command.
```
# perf record -g ocserv
```

After the server is terminated, the output is placed in perf.data.
You may examine the output using:
```
# perf report
```


# Continuous Integration (CI)

We utilize the gitlab-ci continuous integration system. It is used to test
most of the Linux systems (see .gitlab-ci.yml),and is split in two phases,
build image creation and compilation/test. The build image creation is done
at the openconnect/build-images subproject and uploads the image at the gitlab.com
container registry. The compilation/test phase is on every commit to project.


# How the VPN works

Please see the [technical description page](http://ocserv.gitlab.io/www/technical.html).
