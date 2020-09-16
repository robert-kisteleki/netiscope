package util

import (
	"flag"
	"fmt"
	"net"
	"os"

    "github.com/go-ini/ini"
)

var defaultConfig = os.Getenv("HOME") + "/.config/netiscope.ini"
var defaultCIDRConfig = os.Getenv("HOME") + "/.config/netiscope-cidr.ini"

var cfg *ini.File
var cidrCfg *ini.File
var (
	flagConfig    string
	flagCIDR      string
	flagSection   string
	flagSkipIPv4  bool
	flagSkipIPv6  bool
	flagForceIPv4 bool
	flagForceIPv6 bool
	flagLogLevel  string
	flagVerbose   bool
	flagColor     bool

	// network interface check can signal if there were no routable addresses found
	noUsableIPv4 bool
	noUsableIPv6 bool
)

// SetupFlags defines the command line flags we recognise
func SetupFlags() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&flagConfig, "c", "", "Use this config file")
	flag.StringVar(&flagCIDR, "C", "", "Use this CIDR file")
	flag.StringVar(&flagSection, "s", "checks", "Which section lists the checks to execute. Default is 'checks'.")
	flag.BoolVar(&flagSkipIPv4, "skip4", false, "Skip IPv4 checks")
	flag.BoolVar(&flagSkipIPv6, "skip6", false, "Skip IPv6 checks")
	flag.BoolVar(&flagForceIPv4, "force4", false, "Force IPv4 checks even if no usable local IPv4 addresses are found")
	flag.BoolVar(&flagForceIPv6, "force6", false, "Force IPv6 checks even if no usable local IPv6 addresses are found")
	flag.StringVar(&flagLogLevel, "l", "", "Log level. Can be 'detail', 'info', 'warning' or 'error'. Default is 'info'.")
	flag.BoolVar(&flagVerbose, "v", false, "Shorthand to set log level to 'detail'")
	flag.BoolVar(&flagColor, "color", false, "Enable colored output")

	flag.Parse()

	setLogLevel(flagLogLevel)
	if flagVerbose {
		LogLevel = LevelDetail // verbose means detail
	}
}

// ReadConfig deals with main configuration file loading
func ReadConfig() {
	confFile := whichFile(
		[]string{flagConfig, "netiscope.ini", defaultConfig},
	)
	// config as argument is tried first
	if confFile == "" {
		Log("main", LevelFatal, "CONFIG_FLAG", "Failed to find main config file")
		os.Exit(1)
	}

	var err error
	cfg, err = ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true},
		confFile,
	)
	if err != nil {
		Log("main", LevelFatal, "CONFIG_FLAG", fmt.Sprintf("Failed to read main config file: %v", err))
		os.Exit(1)
	}
	Log("main", LevelDetail, "CONFIG_FLAG", "Reading config file "+confFile)

	setLogLevel(cfg.Section("main").Key("loglevel").MustString(""))
}

// ReadCIDRConfig deals with CIDR list loading
func ReadCIDRConfig() {
	confFile := whichFile(
		[]string{flagCIDR, "cidr.ini", defaultCIDRConfig},
	)
	// config as argument is tried first
	if confFile == "" {
		Log("main", LevelWarning, "CONFIG_FLAG", "Failed to find CIDR config file")
		return
	}

	var err error
	cidrCfg, err = ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true},
		confFile,
	)
	if err != nil {
		Log("main", LevelWarning, "CONFIG_FLAG", fmt.Sprintf("Failed to read CIDR config file: %v", err))
		return
	}
	Log("main", LevelDetail, "CONFIG_FLAG", "Reading CIDR config file "+confFile)

	loadProviderCIDRBlocks()
}

// check which file exists, from a list of candidates in order of preference
func whichFile(candidates []string) string {
	for _, file := range candidates {
		if file == "" {
			continue
		}
		_, err := os.Stat(file)
		if err != nil {
			continue
		}
		return file
	}
	return ""
}

func setLogLevel(level string) {
	switch level {
	case "detail":
		LogLevel = LevelDetail
	case "info":
		LogLevel = LevelInfo
	case "warning":
		LogLevel = LevelWarning
	case "error":
		LogLevel = LevelError
	}
}

// GetChecks loads the list of checks to be run from the ini file
func GetChecks() []string {
	return cfg.Section(flagSection).KeyStrings()
}

// GetConfigBoolParam returns the value of a boolean config option
func GetConfigBoolParam(section string, key string, deflt bool) bool {
	return cfg.Section(section).Key(key).MustBool(deflt)
}

// SkipIPv4 decides if IPv4 related checks should be skipped
func SkipIPv4() bool {
	return !flagForceIPv4 && (flagSkipIPv4 || cfg.Section("main").Key("skip_ipv4").MustBool(false) || noUsableIPv4)
}

// SkipIPv6 decides if IPv6 related checks should be skipped
func SkipIPv6() bool {
	return !flagForceIPv6 && (flagSkipIPv6 || cfg.Section("main").Key("skip_ipv6").MustBool(false) || noUsableIPv6)
}

// GetPingCount returns how many ping packets should be sent
func GetPingCount() int {
	return cfg.Section("main").Key("ping_packets").MustInt(3)
}

// ColoredOutput determines if the (terminal) output can use ANSI coloring or nor
func ColoredOutput() bool {
	return flagColor || (cfg != nil && cfg.Section("main").Key("color").MustBool(false))
}

// GetDNSNamesToLookup returns the list of FQDNs to look up with DNS resolvers
func GetDNSNamesToLookup() []string {
	return cfg.Section("dns").Key("name").ValueWithShadows()
}

// GetTLDsToLookup returns the list of TLDs to look up with root DNS servers
func GetTLDsToLookup() []string {
	return cfg.Section("dns").Key("tld").ValueWithShadows()
}

// GetRandomTLDAmount returns how may random domains should be tried against root DNS servers
func GetRandomTLDAmount() int {
	return cfg.Section("dns").Key("random").MustInt(3)
}

// load known CIDR prefixes for some providers
func loadProviderCIDRBlocks() {
	keys := cidrCfg.Section("cidrs").KeyStrings()
	for _, key := range keys {
		cidrProviders[key] = make([]net.IPNet, 0)
		cidrs := cidrCfg.Section("cidrs").Key(key).ValueWithShadows()
		for _, cidr := range cidrs {
			cidrProviders[key] = append(cidrProviders[key], makeIPNet(cidr))
		}
	}
}

// SetFailedIPv4 is called to signal the absence of usable IPv4 addesses
func SetFailedIPv4() {
	noUsableIPv4 = true
	if flagForceIPv4 {
		Log("main", LevelWarning, "FORCE_IPV4", "IPv4 check are forced by configuration")
	}
}

// SetFailedIPv6 is called to signal the absence of usable IPv6 addesses
func SetFailedIPv6() {
	noUsableIPv6 = true
	if flagForceIPv6 {
		Log("main", LevelWarning, "FORCE_IPV6", "IPv6 check are forced by configuration")
	}
}
