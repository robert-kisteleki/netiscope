package checks

import (
	"encoding/base64"
	"fmt"
	"net"
	"netiscope/log"
	"netiscope/util"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHHostKeysCheck struct {
	netiscopeCheckBase
	currentSSHPubkeyHashExpectation string
	currentSSHPubkeyHashReality     string
	checkName                       string
}

// CheckSshHostKeys checks if outgoing SSH connections get the correct host keys or not
func (check *SSHHostKeysCheck) Start() {
	targets := util.GetTargetsToSSHCheck()
	for _, target := range targets {
		if len(target) != 2 {
			check.Log(log.LevelError, "SSH_KEY_CONFIG_ERROR", "Wrong SSH host key check configuration: "+strings.Join(target, ","))
			continue
		}

		host := target[0]
		expectedKey := strings.Split(target[1], " ")[1]

		check.Log(log.LevelDetail, "SSH_KEY_HOST_TO_CHECK", "SSH host key check for host "+host)

		keyBytes, err := base64.StdEncoding.DecodeString(expectedKey)
		if err != nil {
			check.Log(log.LevelError, "SSH_KEY_FORMAT_ERROR1", "Wrong SSH host key format for "+host)
			continue
		}
		hostKey, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
			check.Log(log.LevelError, "SSH_KEY_FORMAT_ERROR2", "Wrong SSH host key format for "+host)
			continue
		}
		check.currentSSHPubkeyHashExpectation = hostKey.Type() + " " + ssh.FingerprintSHA256(hostKey)

		sshConfig := &ssh.ClientConfig{
			HostKeyCallback: check.hostKeyCheckCallback,
		}
		_, err = ssh.Dial("tcp", host, sshConfig)
		if check.currentSSHPubkeyHashExpectation != check.currentSSHPubkeyHashReality {
			check.Log(log.LevelError, "SSH_KEY_CHECK_FAIL",
				fmt.Sprintf("SSH host key mismatch for %s: expected %s, got %s",
					host,
					check.currentSSHPubkeyHashExpectation,
					check.currentSSHPubkeyHashReality,
				),
			)
		} else {
			check.Log(log.LevelInfo, "SSH_KEY_CHECK_SUCCESS", fmt.Sprintf("SSH host key match for %s", host))
		}
	}
	check.Log(log.LevelInfo, "FINISH", "Finished")
}

func (check *SSHHostKeysCheck) hostKeyCheckCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	check.currentSSHPubkeyHashReality = key.Type() + " " + ssh.FingerprintSHA256(key)
	if check.currentSSHPubkeyHashExpectation != check.currentSSHPubkeyHashReality {
		return fmt.Errorf("SSH host key mismatch")
	} else {
		return nil
	}
}
