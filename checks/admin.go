package checks

type NetiscopeAdminCheck struct {
	netiscopeCheckBase
}

func (check NetiscopeAdminCheck) start() {
	check.netiscopeCheckBase.start()
}

func (check NetiscopeAdminCheck) Log(
	level LogLevelType,
	mnemonic string,
	details string,
) {
	check.netiscopeCheckBase.log(level, mnemonic, details)
}

var AdminCheck NetiscopeAdminCheck

func init() {
	AdminCheck = NetiscopeAdminCheck{
		netiscopeCheckBase: netiscopeCheckBase{
			name: "admin",
		},
	}
}
