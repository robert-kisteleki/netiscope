package util

import (
	"flag"
	"fmt"
	"net"
	"os"

	"gopkg.in/ini.v1" //    https://github.com/go-ini/ini
)

const defaultConfig = ".config/netiscope.ini"

var cfg *ini.File
var (
	flagConfig   string
	flagSection  string
	flagSkipIPv4 bool
	flagSkipIPv6 bool
	flagLogLevel string
	flagVerbose  bool
	flagColor    bool
)

// SetupFlags defines the command line flags we recognise
func SetupFlags() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&flagConfig, "c", "", "Use this config file")
	flag.StringVar(&flagSection, "s", "checks", "Which section lists the checks to execute. Default is 'checks'.")
	flag.BoolVar(&flagSkipIPv4, "skip4", false, "Skip IPv4 checks")
	flag.BoolVar(&flagSkipIPv6, "skip6", false, "Skip IPv6 checks")
	flag.StringVar(&flagLogLevel, "l", "", "Log level. Can be 'detail', 'info', 'warning' or 'error'. Default is 'info'.")
	flag.BoolVar(&flagVerbose, "v", false, "Shorthand to set log level to 'detail'")
	flag.BoolVar(&flagColor, "color", false, "Enable colored output")

	flag.Parse()

	setLogLevel(flagLogLevel)
	if flagVerbose {
		LogLevel = LevelDetail // verbose means detail
	}
}

// ReadConfig deals wih configuration file loading
func ReadConfig() {
	// config as argument is tried first
	if flagConfig != "" {
		err := tryConfig(flagConfig)
		if err != nil {
			Log("main", LevelFatal, "CONFIG_FLAG", fmt.Sprintf("Failed to read config file: %v", err))
			os.Exit(1)
		}
		Log("main", LevelDetail, "CONFIG_FLAG", "Reading config file "+flagConfig)
	} else {
		home := os.Getenv("HOME")
		configFile := home + "/" + defaultConfig
		err := tryConfig(configFile)
		if err != nil {
			Log("main", LevelFatal, "CONFIG_FLAG", fmt.Sprintf("Failed to read config file: %v", err))
			os.Exit(1)
		}
		Log("main", LevelDetail, "CONFIG_DEFAULT", "Reading config file "+configFile)
	}

	setLogLevel(cfg.Section("main").Key("loglevel").MustString(""))
	loadProviderCIDRBlocks()
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

func tryConfig(confFile string) error {
	var err error
	cfg, err = ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true},
		confFile,
	)
	return err
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
	return flagSkipIPv4 || cfg.Section("main").Key("skip_ipv4").MustBool(false)
}

// SkipIPv6 decides if IPv4 related checks should be skipped
func SkipIPv6() bool {
	return flagSkipIPv6 || cfg.Section("main").Key("skip_ipv6").MustBool(false)
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

// load known CIDR prefixes for some providers
func loadProviderCIDRBlocks() {
	keys := cfg.Section("cidrs").KeyStrings()
	for _, key := range keys {
		cidrProviders[key] = make([]net.IPNet, 0)
		cidrs := cfg.Section("cidrs").Key(key).ValueWithShadows()
		for _, cidr := range cidrs {
			cidrProviders[key] = append(cidrProviders[key], makeIPNet(cidr))
		}
	}
}
