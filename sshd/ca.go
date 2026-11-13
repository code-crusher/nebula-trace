package sshd

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// groupsExtension is the certificate extension sshd reads the allowed groups from
const groupsExtension = "groups@nebula"

// certAuthority is a trusted CA for user certificates, optionally limited to the users and groups
// a certificate it signed may carry.
type certAuthority struct {
	key ssh.PublicKey

	// users is the allow_users option, nil means any user
	users []string
	// groups is the allow_groups option, nil means any group
	groups []string
}

func keysEqual(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// authorizeCert checks cert against the limits of the CA that signed it. The CA's signature is
// already verified by the time this runs, so what remains is authorization: which users the
// certificate may log in as, and which groups it must carry. When the same CA key is configured
// more than once, every entry's limits apply.
func (s *SSHServer) authorizeCert(user string, cert *ssh.Certificate) error {
	s.authLock.RLock()
	defer s.authLock.RUnlock()

	authorized := false
	for _, ca := range s.trustedCAs {
		if !keysEqual(ca.key, cert.SignatureKey) {
			continue
		}
		authorized = true

		if len(ca.users) > 0 && !slices.Contains(ca.users, user) {
			return fmt.Errorf("user %q is not allowed by the CA policy", user)
		}
		if len(ca.groups) > 0 {
			var found bool
			for _, g := range certGroups(cert) {
				if slices.Contains(ca.groups, g) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("certificate carries none of the CA's allowed groups")
			}
		}
	}

	if !authorized {
		// Unreachable: IsUserAuthority already accepted the CA that signed cert
		return fmt.Errorf("certificate signed by unrecognized authority")
	}
	return nil
}

// certGroups returns the groups a certificate carries in its groups@nebula extension, a comma
// separated list, "sysadmins, team-dev1". A certificate without the extension carries no groups.
func certGroups(cert *ssh.Certificate) []string {
	raw, ok := cert.Extensions[groupsExtension]
	if !ok {
		return nil
	}

	var groups []string
	for _, g := range strings.Split(raw, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

// isUserAuthority reports whether key is a CA this server trusts to sign user certificates
func (s *SSHServer) isUserAuthority(key ssh.PublicKey) bool {
	s.authLock.RLock()
	defer s.authLock.RUnlock()
	return slices.ContainsFunc(s.trustedCAs, func(ca certAuthority) bool {
		return keysEqual(ca.key, key)
	})
}

// parseCACert parses a CA public key, as a file path or a public key string
func parseCACert(pubKey string) (ssh.PublicKey, error) {
	if b, err := os.ReadFile(pubKey); err == nil {
		pubKey = string(b)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return nil, fmt.Errorf("not a public key or readable file: %s", pubKey)
	}
	return pk, nil
}
