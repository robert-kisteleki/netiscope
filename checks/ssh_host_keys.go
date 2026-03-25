package checks

import (
	"encoding/base64"
	"fmt"
	"net"
	"netiscope/util"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHHostKeysCheck struct {
	netiscopeCheckBase
	targets        []string
	keys           map[string][]string
	currentTarget  string
	offeredKey     string
	OfferedKeyHash string
	matckedKey     string
}

func (check *SSHHostKeysCheck) configure() {
	check.targets = make([]string, 0)
	check.keys = make(map[string][]string, 0)

	servers := util.GetTargetsToSSHCheck()
	for _, target := range servers {
		if len(target) != 2 {
			check.log(LogLevelError, "SSH_KEY_CONFIG_ERROR", "Wrong SSH host key check configuration: "+strings.Join(target, ","))
			continue
		}
		if !slices.Contains(check.targets, target[0]) {
			check.targets = append(check.targets, target[0])
		}
		check.keys[target[0]] = append(check.keys[target[0]], target[1])
		check.log(
			LogLevelDetail,
			"SSH_KEY_CONFIG_LOADED",
			fmt.Sprintf("Loaded SSH key for target %s: %s", target[0], target[1]),
		)
	}
}

// SSHHostKeysCheck checks if outgoing SSH connections get the correct host keys or not
func (check *SSHHostKeysCheck) start() {
	check.netiscopeCheckBase.start()

	for _, target := range check.targets {
		if check.stopping {
			return
		}

		host := strings.Split(target, ",")[0]
		check.currentTarget = host
		check.matckedKey = ""

		check.log(LogLevelDetail, "SSH_KEY_HOST_TO_CHECK", "SSH host key check for host "+host)

		sshConfig := &ssh.ClientConfig{
			HostKeyCallback: check.hostKeyCheckCallback,
			User:            "netiscope",
		}
		_, err := ssh.Dial("tcp", host, sshConfig)
		switch {
		case check.matckedKey == "":
			check.log(LogLevelError, "SSH_KEY_CHECK_FAIL",
				fmt.Sprintf("SSH host key mismatch for %s: got %s (%s). Error is %v.",
					host,
					check.offeredKey,
					check.OfferedKeyHash,
					err,
				),
			)
		case check.matckedKey != "":
			check.log(
				LogLevelInfo,
				"SSH_KEY_CHECK_SUCCESS",
				fmt.Sprintf("SSH host key match for %s: %s (%s)", host, check.matckedKey, check.OfferedKeyHash),
			)
		}
	}

	check.netiscopeCheckBase.finish()
}

func (check *SSHHostKeysCheck) hostKeyCheckCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	check.offeredKey = key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
	check.OfferedKeyHash = key.Type() + " " + ssh.FingerprintSHA256(key)
	check.log(LogLevelDetail, "SSH_KEY_HOST_OFFERED", "SSH host key offered: "+check.offeredKey)
	for _, keyTry := range check.keys[check.currentTarget] {
		if check.offeredKey == keyTry {
			check.matckedKey = keyTry
			return nil
		}
	}
	return fmt.Errorf("SSH host key mismatch")
}
