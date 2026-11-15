package nebula

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
	"golang.org/x/crypto/ssh"
)

func wireSSHReload(l *slog.Logger, ssh *sshd.SSHServer, c *config.C) {
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		if c.GetBool("sshd.enabled", false) {
			// Restarting the server drops every open session, the one that asked for this reload included. Only restart
			// when it isn't running or its config changed. The host key and authorized_keys files can change under the
			// same config, new handshakes use them without a restart
			if ssh.Running() && !slices.ContainsFunc(sshdServerKeys, c.HasChanged) {
				key, err := loadSSHHostKey(c)
				if err == nil {
					err = ssh.SetHostKey(key)
				}
				if err != nil {
					l.Error("Failed to reconfigure the sshd", "error", err)
					ssh.Stop()
					r.Failed()
					return
				}
				// The key files can change under the same config, so pick up their new contents without a restart.
				// Unlike a config change, a file that fails to read here leaves the keys we have in place rather
				// than replacing them with a partial set.
				cas, users, ok := readSSHKeys(l, c, r)
				if ok {
					setSSHKeys(l, ssh, cas, users, r)
				}
				return
			}
			sshRun, err := configSSH(l, ssh, c, r)
			if err != nil {
				l.Error("Failed to reconfigure the sshd", "error", err)
				ssh.Stop()
				r.Failed()
			}
			if sshRun != nil {
				go sshRun()
			}
		} else {
			ssh.Stop()
		}
	})
}

// sshdServerKeys are what configSSH reads
var sshdServerKeys = []string{"sshd.enabled", "sshd.listen", "sshd.host_key", "sshd.trusted_cas", "sshd.authorized_users"}

// loadSSHHostKey returns sshd.host_key, read from its file when it names one.
func loadSSHHostKey(c *config.C) ([]byte, error) {
	hostKeyPathOrKey := c.GetString("sshd.host_key", "")
	if hostKeyPathOrKey == "" {
		return nil, fmt.Errorf("sshd.host_key must be provided")
	}
	if strings.Contains(hostKeyPathOrKey, "-----BEGIN") {
		return []byte(hostKeyPathOrKey), nil
	}
	b, err := os.ReadFile(hostKeyPathOrKey)
	if err != nil {
		return nil, fmt.Errorf("error while loading sshd.host_key file: %s", err)
	}
	return b, nil
}

// configSSH reads the ssh info out of the passed-in Config and
// updates the passed-in SSHServer. On success, it returns a function
// that callers may invoke to run the configured ssh server. On
// failure, it returns nil, error.
// r is nil at startup, entries that are skipped with a warning fail it on a reload
func configSSH(l *slog.Logger, ssh *sshd.SSHServer, c *config.C, r *config.Reload) (func(), error) {
	listen := c.GetString("sshd.listen", "")
	if listen == "" {
		return nil, fmt.Errorf("sshd.listen must be provided")
	}

	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("invalid sshd.listen address: %s", err)
	}
	if port == "22" {
		return nil, fmt.Errorf("sshd.listen can not use port 22")
	}

	hostKeyBytes, err := loadSSHHostKey(c)
	if err != nil {
		return nil, err
	}

	err = ssh.SetHostKey(hostKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error while adding sshd.host_key: %s", err)
	}

	cas, users, _ := readSSHKeys(l, c, r)
	setSSHKeys(l, ssh, cas, users, r)

	var runner func()
	if c.GetBool("sshd.enabled", false) {
		ssh.Stop()
		runner = func() {
			if err := ssh.Run(listen); err != nil {
				l.Warn("Failed to run the SSH server", "error", err)
			}
		}
	} else {
		ssh.Stop()
	}

	return runner, nil
}

// loadSSHAuthorizedKeys returns the public keys named by one sshd.authorized_users keys entry. An entry is either a
// key or the path of a file in the authorized_keys format, which may hold any number of keys as well as comments and
// blank lines.
func loadSSHAuthorizedKeys(keyOrPath string) ([]string, error) {
	// A key parses as one, so anything else is the path of a file holding them
	keyOrPath = strings.TrimSpace(keyOrPath)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyOrPath)); err == nil {
		return []string{keyOrPath}, nil
	}

	b, err := os.ReadFile(keyOrPath)
	if err != nil {
		return nil, fmt.Errorf("not an ssh public key or a readable file: %s", err)
	}

	var keys []string
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse here rather than in the caller so an error names the file and the line it is on
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", keyOrPath, i+1, err)
		}
		keys = append(keys, line)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no ssh keys found in sshd authorized_keys file %s", keyOrPath)
	}

	return keys, nil
}

// setSSHKeys replaces the trusted CAs and authorized keys with cas and users.
func setSSHKeys(l *slog.Logger, ssh *sshd.SSHServer, cas []string, users map[string][]string, r *config.Reload) {
	// Clear existing trusted CAs and authorized keys
	ssh.ClearTrustedCAs()
	ssh.ClearAuthorizedKeys()

	for _, caAuthorizedKey := range cas {
		err := ssh.AddTrustedCA(caAuthorizedKey)
		if err != nil {
			l.Warn("SSH CA had an error, ignoring", "error", err, "sshCA", caAuthorizedKey)
			r.Failed()
		}
	}

	for user, keys := range users {
		for _, key := range keys {
			err := ssh.AddAuthorizedKey(user, key)
			if err != nil {
				l.Warn("Failed to authorize key",
					"error", err,
					"sshKey", key,
					"sshUser", user,
				)
				r.Failed()
			}
		}
	}
}

// readSSHKeys reads the trusted CAs and authorized keys the config names, key files included. It reports whether
// every entry could be read.
func readSSHKeys(l *slog.Logger, c *config.C, r *config.Reload) (cas []string, users map[string][]string, ok bool) {
	ok = true
	cas = c.GetStringSlice("sshd.trusted_cas", []string{})

	rawKeys := c.Get("sshd.authorized_users")
	entries, isList := rawKeys.([]any)
	if !isList {
		if r == nil {
			l.Info("no ssh users to authorize")
		}
		return cas, nil, ok
	}

	users = make(map[string][]string, len(entries))
	for _, rk := range entries {
		kDef, isMap := rk.(map[string]any)
		if !isMap {
			l.Warn("Authorized user had an error, ignoring", "sshKeyConfig", rk)
			r.Failed()
			ok = false
			continue
		}

		user, isString := kDef["user"].(string)
		if !isString {
			l.Warn("Authorized user is missing the user field", "sshKeyConfig", rk)
			r.Failed()
			ok = false
			continue
		}

		var keyOrPaths []string
		switch v := kDef["keys"].(type) {
		case string:
			keyOrPaths = []string{v}

		case []any:
			for _, subK := range v {
				sk, isString := subK.(string)
				if !isString {
					l.Warn("Did not understand ssh key",
						"sshKeyConfig", rk,
						"sshKey", subK,
					)
					r.Failed()
					ok = false
					continue
				}
				keyOrPaths = append(keyOrPaths, sk)
			}

		default:
			l.Warn("Authorized user is missing the keys field or was not understood", "sshKeyConfig", rk)
			r.Failed()
			ok = false
			continue
		}

		for _, keyOrPath := range keyOrPaths {
			keys, err := loadSSHAuthorizedKeys(keyOrPath)
			if err != nil {
				l.Warn("Failed to authorize key",
					"error", err,
					"sshKeyConfig", rk,
					"sshKey", keyOrPath,
				)
				r.Failed()
				ok = false
				continue
			}
			users[user] = append(users[user], keys...)
		}
	}

	return cas, users, ok
}
