CHANGES
=======

0.1.20200723
  * added DNS queries to dns_open_resolvers and refactored to share code with dns_local_resolvers
  * added a "Quick Start" section to docs
  * separate CIDR blocks list from the main config file into a separate one (cidr.ini)
  * make config loading prefer command line parameters, then local directory, then the default location

0.0.1.20200505
  * initial release
  * modules: network_interfaces, dns_local_resolvers, dns_open_resolvers (preliminary)
