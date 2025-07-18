## CHANGES

next
  * ...

0.6.20250714
  * CHANGED: run checks asynchronously
  * CHANGED: b-root changed IP addresses
  * NEW: run a specific test only
  * NEW: show progress in verbose mode
  * NEW: GUI (start with `-gui`)
  * NEW: add `-version` to options

0.5.20231118
  * updated to go1.21
  * updated packages
  * replace (abandoned) go-ping with pro-bing
  * updated CIDR ranges

0.4.20200927
  * updated DoH checks to support RFC8484
  * restructured the DNS measurement code to support the on-the-wire format needed for RFC8484

0.4.20200925
  * added a report on how many entries were made in the log, per log level (detail, info, warning, ...)
  * added checks for DoH (DNS over HTTPS)

0.3.20200919
  * switched to use go modules for dependencies
  * added a little server tool to reply to UDP or TCP connections
  * added port filtering checks

0.2.20200914
  * added dns root servers check (ping, query SOA, query known TLDs, query random TLDs)
  * further unification of local and open resolver check code
  * skip checks for IPv4/IPv6 if no relevant network interfaces are found
    and add `force4` and `force6` parameters to override this

0.1.20200723
  * added DNS queries to dns_open_resolvers and refactored to share code with dns_local_resolvers
  * added a "Quick Start" section to docs
  * separate CIDR blocks list from the main config file into a separate one (cidr.ini)
  * make config loading prefer command line parameters, then local directory, then the default location

0.0.1.20200505
  * initial release
  * modules: network_interfaces, dns_local_resolvers, dns_open_resolvers (preliminary)
