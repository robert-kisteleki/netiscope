package util

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

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
	flagRunCheck  string
	flagGui       bool
	GuiIPv4       bool
	GuiIPv6       bool

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
	flag.StringVar(&flagLogLevel, "l", "", "Log level. Can be 'detail', 'info', 'warning' or 'error'")
	flag.BoolVar(&flagVerbose, "v", false, "Be verbose reporting progress")
	flag.StringVar(&flagRunCheck, "check", "", "Run only this check")
	flag.BoolVar(&flagGui, "gui", false, "Start with a browser GUI")

	flag.Parse()
}

// ReadConfig deals with main configuration file loading
func ReadConfig() {
	confFile := whichFile(
		[]string{flagConfig, "netiscope.ini", defaultConfig},
	)
	// config as argument is tried first
	if confFile == "" {
		fmt.Fprintf(os.Stderr, "Failed to find main config file")
		os.Exit(1)
	}

	var err error
	cfg, err = ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true},
		confFile,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read main config file: %v", err)
		os.Exit(1)
	}
}

// ReadCIDRConfig deals with CIDR list loading
func ReadCIDRConfig() {
	confFile := whichFile(
		[]string{flagCIDR, "cidr.ini", defaultCIDRConfig},
	)
	// config as argument is tried first
	if confFile == "" {
		fmt.Fprintf(os.Stderr, "Failed to find CIDR config file")
		return
	}

	var err error
	cidrCfg, err = ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true},
		confFile,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read CIDR config file: %v", err)
		return
	}

	loadProviderCIDRBlocks()
}

// GetChecks loads the list of checks to be run from the ini file
func GetChecks() []string {
	if flagRunCheck != "" {
		return []string{flagRunCheck}
	}
	return cfg.Section(flagSection).KeyStrings()
}

// GetConfigBoolParam returns the value of a boolean config option
func GetConfigBoolParam(section string, key string, deflt bool) bool {
	return cfg.Section(section).Key(key).MustBool(deflt)
}

// SkipIPv4 decides if IPv4 related checks should be skipped
func SkipIPv4() bool {
	if flagGui {
		return !GuiIPv4
	} else {
		return !flagForceIPv4 && (flagSkipIPv4 || cfg.Section("main").Key("skip_ipv4").MustBool(false) || noUsableIPv4)
	}
}

// SkipIPv6 decides if IPv6 related checks should be skipped
func SkipIPv6() bool {
	if flagGui {
		return !GuiIPv6
	} else {
		return !flagForceIPv6 && (flagSkipIPv6 || cfg.Section("main").Key("skip_ipv6").MustBool(false) || noUsableIPv6)
	}
}

// GetPingCount returns how many ping packets should be sent
func GetPingCount() int {
	return cfg.Section("main").Key("ping_packets").MustInt(3)
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
		fmt.Fprintf(os.Stderr, "IPv4 check are forced by configuration")
	}
}

// SetFailedIPv6 is called to signal the absence of usable IPv6 addesses
func SetFailedIPv6() {
	noUsableIPv6 = true
	if flagForceIPv6 {
		fmt.Fprintf(os.Stderr, "IPv6 check are forced by configuration")
	}
}

// GetTargetsToPortCheck returns the list of [target,port,protocol] to check for port filtering
func GetTargetsToPortCheck() [][]string {
	return splitConfigKeyList("port_filtering", "port_check")
}

// CheckPortFilteringResponse decides if answers to port filtering queries should be checked
func CheckPortFilteringResponse() bool {
	return cfg.Section("port_filtering").Key("netiscope_response").MustBool(false)
}

// GetPortFilteringTimeout specifies the network timeout (seconds) for port filtering checks
func GetPortFilteringTimeout() int {
	return cfg.Section("port_filtering").Key("timeout").MustInt(3)
}

// GetDoHProviders returns the list of DoH providers listed in the config file
func GetDoHProviders() [][]string {
	return splitConfigKeyList("doh", "provider")
}

func Verbose() bool {
	return flagVerbose
}

func StartGui() bool {
	return flagGui || cfg.Section("main").Key("gui").MustBool(false)
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

// split entries in a a section/key list at the "," separator
func splitConfigKeyList(section string, key string) [][]string {
	list := cfg.Section(section).Key(key).ValueWithShadows()
	var splitList [][]string
	for _, item := range list {
		splitList = append(splitList, strings.Split(item, ","))
	}
	return splitList
}

func GetLogLevel() string {
	if flagLogLevel != "" {
		return flagLogLevel
	} else {
		return cfg.Section("main").Key("loglevel").MustString("")
	}
}
