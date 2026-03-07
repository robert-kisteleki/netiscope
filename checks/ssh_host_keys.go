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

var currentSSHPubkeyHashExpectation string
var currentSSHPubkeyHashReality string
var checkName string

// CheckSshHostKeys checks if outgoing SSH connections get the correct host keys or not
func CheckSSHHostKeys(check *log.Check) {
	defer close(check.Tracker)

	checkName = check.Name

	targets := util.GetTargetsToSSHCheck()
	for _, target := range targets {
		if len(target) != 2 {
			log.NewResultItem(check, log.LevelError, "SSH_KEY_CONFIG_ERROR", "Wrong SSH host key check configuration: "+strings.Join(target, ","))
			continue
		}

		host := target[0]
		expectedKey := strings.Split(target[1], " ")[1]

		log.NewResultItem(check, log.LevelDetail, "SSH_KEY_HOST", "SSH host key check for host "+host)

		keyBytes, err := base64.StdEncoding.DecodeString(expectedKey)
		if err != nil {
			log.NewResultItem(check, log.LevelError, "SSH_KEY_FORMAT_ERROR1", "Wrong SSH host key format for "+host)
			continue
		}
		hostKey, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
			log.NewResultItem(check, log.LevelError, "SSH_KEY_FORMAT_ERROR2", "Wrong SSH host key format for "+host)
			continue
		}
		currentSSHPubkeyHashExpectation = hostKey.Type() + " " + ssh.FingerprintSHA256(hostKey)

		sshConfig := &ssh.ClientConfig{
			HostKeyCallback: hostKeyCheckCallback,
		}
		_, err = ssh.Dial("tcp", host, sshConfig)
		if currentSSHPubkeyHashExpectation != currentSSHPubkeyHashReality {
			log.NewResultItem(check, log.LevelError, "SSH_KEY_CHECK",
				fmt.Sprintf("SSH host key mismatch for %s: expected %s, got %s",
					host,
					currentSSHPubkeyHashExpectation,
					currentSSHPubkeyHashReality,
				),
			)
		} else {
			log.NewResultItem(check, log.LevelInfo, "SSH_KEY_CHECK",
				fmt.Sprintf("SSH host key match for %s", host),
			)
		}
	}
	log.NewResultItem(check, log.LevelInfo, "FINISH", "Finished")
}

func hostKeyCheckCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	currentSSHPubkeyHashReality = key.Type() + " " + ssh.FingerprintSHA256(key)
	if currentSSHPubkeyHashExpectation != currentSSHPubkeyHashReality {
		return fmt.Errorf("SSH host key mismatch")
	} else {
		return nil
	}
}
