# Netiscope

A simple command line (CLI) tool to check network connectivity.

**Netiscope** is meant to be a helper tool to be used in case the network doesn't seem to be working properly, and can give hints about what's going wrong. There is not a lot of secret sauce to this tool: a seasoned user can do these check themselves with various tools to determine the root cause of a problem. However, **Netiscope** may make this task simpler.

**Netiscope** is open source and can be extended with more checks.

## Quick Start Guide

In order to compile, you need to install [Golang](https://golang.org/). Then, to get the source for Netiscope:

```
mkdir -p ~/go/src/
cd ~/go/src/
git clone https://github.com/robert-kisteleki/netiscope.git
```

There are a few Go packages that are required to compile:

```
go get github.com/miekg/dns
go get github.com/fatih/color
go get github.com/sparrc/go-ping
go get gopkg.in/ini.v1
```

Now you're ready to compile and run:

```
go build netiscope
./netiscope -c netiscope.ini
```

On Linux, the ping functionality may need '"unprivileged" ping via UDP" permission:

```
sudo sysctl -w net.ipv4.ping_group_range="0   2147483647"
```


## Checks

**Netiscope** executes a series of _checks_, each tailored to discover if a particular networking function is working properly or not.

The default output contains lines of [timestamp, check, level, details].

### 1. Local network interfaces

Check if any routable addresses are present. Current unicast IPv4 and IPv6 addresses are evaluated on each interface. Special addresses (such as RFC1918) are marked.

### 2. Local DNS resolvers

Check if DNS resolvers are defined, reachable and if they work properly. Each resolver defined in resolv.conf is pinged and a series of DNS lookups (for well known targets such as google.com) are executed agains them. The results are matched against a known-good list of potential responses.

### 3. Open DNS resolvers

Check if well-known open DNS resolvers are reachable. "Well-known" includes 1.1.1. (Cloudflare), 8.8.8.8 (Google) and 9.9.9.9 (Quad9). They are currently only pinged.

TODO: implement proper checks

### X. Future checks

The checks could also include:
  * (TODO, possible) Wifi signal/noise/channel/rate/packet loss/...
  * (TODO, possible) Check of DoT (DNS over TLS) or DoH (DNS over HTTPS) are available and working
  * (TODO, possible) Query root name servers and/or traceroute to them
  * (TODO, possible) Traceroute to known targets (M-Lab, RIPE Atlas anchors, ...)
  * (TODO, possible) Detect presence of a captive portal
  * (TODO, possible) Availability of popular services (google, facebook, ...), perhaps including:
    * IP based (as opposed to DNS based) to detect DNS censorship
    * verification of TLS certificates
    * sanity check of responses
    * whether protocols such as QUIC can be used
  * (TODO, possible) IPv6 PMTUD to various targets
  * (TODO, possible) Check ability to spoof packets / BCP38 compliance
  * (TODO, possible) User define check: favourite VPN, personal webserver, ... using ping/HTTPS/etc


## Configuration

See `netiscope.ini` for details. This configuration is loaded on start. It can be loaded from `~/.config/netiscope.ini` or explicitly specified via the `-c` parameter.

Notable command line options:
  * `-c CONFIG` specifies a config file
  * `-s SECTION` specifies a configuration section list sthe checks to execute instead of `checks`
  * `-skip4` and `-skip6` disable IPV4/IPv6 checks, respectively
  * `-l LEVEL` sets the log level. LEVEL can be _detail_, _info_ (default), _warning_ or _error_
  * `-v` is a shorthand to increase logging to _detail_ level
  * `-color` enables (ANSI) output colors

The _configuration file_ has several sections:
  * The `main` section has basic options, many which can also be set on the command line:
    * `loglevel`
    * `color`
    * `skip_ipv4` and `skip_ipv6`
    * `ping_packets`
  * The `checks` section lists the checks to execute
    * Each _check_ has (or can have) its own section defining options for the particular check
  * The `cidrs` section contains the list of CIDR blocks for (some) providers. This allows checking
    if the IP address used (or looked up) for that provider is in this "known good" list
  * See the sections and comments in the supplied config file for more details, examples and default settings


## Author

Robert Kisteleki (kistel@gmail.com)


## License and Feedback

The code is open sourced under GPLv3 license. It is available at [https://github.com/robert-kisteleki/netiscope/](https://github.com/robert-kisteleki/netiscope/).
