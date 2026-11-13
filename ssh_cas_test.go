package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// sshCAHarness builds on the reload harness: it stands up a CA, signs a user certificate for it,
// and connects with the certificate against a server configured by certificate_authorities.
type sshCAHarness struct {
	*sshdReloadHarness

	caSigner ssh.Signer
	// caPub is the CA's authorized-key line, ready for a keys entry
	caPub string
}

func newSSHCAHarness(t *testing.T) *sshCAHarness {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caKey)
	require.NoError(t, err)

	h := &sshCAHarness{
		sshdReloadHarness: newSSHDReloadHarness(t),
		caSigner:          caSigner,
		caPub:             string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())),
	}
	return h
}

// userCert signs a user certificate for the harness's key, carrying the extensions and principals
func (h *sshCAHarness) userCert(t *testing.T, extensions map[string]string, principals ...string) ssh.AuthMethod {
	t.Helper()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             h.signer.PublicKey(),
		KeyId:           "test",
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Extensions:      extensions,
	}
	require.NoError(t, cert.SignCert(rand.Reader, h.caSigner))
	certSigner, err := ssh.NewCertSigner(cert, h.signer)
	require.NoError(t, err)
	return ssh.PublicKeys(certSigner)
}

// connectCert dials the server authenticating with the given method as the given user. It waits
// for the server to be listening first, a reload restarts it on a new port.
func (h *sshCAHarness) connectCert(t *testing.T, user string, auth ssh.AuthMethod) error {
	t.Helper()
	var addr string
	require.Eventually(t, func() bool {
		if a := h.server.Addr(); a != nil && h.server.Running() {
			addr = a.String()
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)

	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err == nil {
		// Leaving sessions open would exhaust the server's channels across the matrix
		_ = c.Close()
	}
	return err
}

// TestSSHCertificateAuthorities exercises the sshd.certificate_authorities option: a CA entry
// with no limits admits any certificate it signed, allow_users and allow_groups narrow what it
// admits, and a malformed entry fails the reload while the valid ones are still used.
func TestSSHCertificateAuthorities(t *testing.T) {
	t.Run("unrestricted CA allows any certificate it signed", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - keys: [%q]\n", h.caPub)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
	})

	t.Run("allow_users limits which user may log in", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - allow_users: [test]\n      keys: [%q]\n", h.caPub)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
		require.Error(t, h.connectCert(t, "other", h.userCert(t, nil, "other")))
	})

	t.Run("allow_groups requires a matching certificate group", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - allow_groups: [sysadmins, team-dev1]\n      keys: [%q]\n", h.caPub)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, map[string]string{"groups@nebula": "sysadmins"}, "test")))
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, map[string]string{"groups@nebula": "team-dev1, sysadmins"}, "test")))
		require.Error(t, h.connectCert(t, "test", h.userCert(t, map[string]string{"groups@nebula": "interns"}, "test")))
		require.Error(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
	})

	t.Run("a certificate from an untrusted CA is refused", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - allow_groups: [sysadmins]\n      keys: [%q]\n", h.caPub)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)

		_, otherCA, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		otherSigner, err := ssh.NewSignerFromKey(otherCA)
		require.NoError(t, err)

		cert := &ssh.Certificate{
			CertType:        ssh.UserCert,
			Key:             h.signer.PublicKey(),
			KeyId:           "test",
			ValidPrincipals: []string{"test"},
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
			Extensions:      map[string]string{"groups@nebula": "sysadmins"},
		}
		require.NoError(t, cert.SignCert(rand.Reader, otherSigner))
		certSigner, err := ssh.NewCertSigner(cert, h.signer)
		require.NoError(t, err)
		require.Error(t, h.connectCert(t, "test", ssh.PublicKeys(certSigner)))
	})

	t.Run("a bad entry fails the reload, the valid ones are still used", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - keys: [%q]\n    - keys: [nope]\n    - not a map\n    - allow_users: nope\n      keys: [%q]\n    - keys: 5\n",
			h.caPub, h.caPub)
		res := h.c.ReloadConfigString(h.config())
		require.NoError(t, res.Err)
		assert.True(t, res.Failed)
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
	})

	t.Run("the limits of every entry for the same CA apply", func(t *testing.T) {
		h := newSSHCAHarness(t)
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - keys: [%q]\n    - allow_groups: [sysadmins]\n      keys: [%q]\n",
			h.caPub, h.caPub)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)
		// The unrestricted entry does not undo the restricted one
		require.Error(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, map[string]string{"groups@nebula": "sysadmins"}, "test")))
	})

	t.Run("a CA key may be a path to a file", func(t *testing.T) {
		h := newSSHCAHarness(t)
		caFile := filepath.Join(t.TempDir(), "user_ca_key.pub")
		require.NoError(t, os.WriteFile(caFile, []byte(h.caPub), 0o600))
		h.extra = fmt.Sprintf("  certificate_authorities:\n    - keys: [%q]\n", caFile)
		require.NoError(t, h.c.ReloadConfigString(h.config()).Err)
		require.NoError(t, h.connectCert(t, "test", h.userCert(t, nil, "test")))
	})
}
