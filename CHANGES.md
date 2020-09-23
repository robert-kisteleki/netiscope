## CHANGES

0.x
  * added a report on how many entries were made in the log, per log level (detail, info, warning, ...)

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
