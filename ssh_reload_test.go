package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestReloadCommandReportsTheResult(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(body), 0o600))
	}
	write("a: 1\nb: 1")
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.Load(dir))
	fail := false
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		r.RestartRequiredIfChanged("b")
		if fail {
			r.Failed()
		}
	})

	// reload reports what happened. A reload that failed is a refusal, exit 1 over ssh;
	// one that merely needs a restart is not.
	reload := func(failed bool) string {
		res := runReload(l, c)
		assert.Equal(t, !failed, res.OK)
		return res.Reason
	}

	write("a: 2\nb: 1")
	assert.Equal(t, "Config reload complete", reload(false))

	fail = true
	write("a: 3\nb: 1")
	assert.Equal(t, "Config reload completed with errors, review the logs", reload(true))

	fail = false
	write("a: 3\nb: 2")
	assert.Equal(t, "Config reload was completed but requires a restart to fully apply, keys [b]", reload(false))

	write("a: [")
	reason := reload(true)
	assert.Contains(t, reason, "Config reload failed, the new config did not load")
	assert.Contains(t, reason, dir, "names the config that did not load")
}

// An authorized_users keys entry is a key or the path of an authorized_keys file. The file may hold any number of keys
// along with comments and blank lines, and a file with no keys in it is an error.
func TestLoadSSHAuthorizedKeys(t *testing.T) {
	key := func(t *testing.T) string {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(priv)
		require.NoError(t, err)
		return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	}
	one, two := key(t), key(t)

	write := func(t *testing.T, body string) string {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}

	t.Run("an inline key is returned as is", func(t *testing.T) {
		got, err := loadSSHAuthorizedKeys(one)
		require.NoError(t, err)
		assert.Equal(t, []string{strings.TrimSpace(one)}, got)
	})

	t.Run("every key in a file is returned, comments and blank lines skipped", func(t *testing.T) {
		path := write(t, "# a comment\n\n"+one+"\n   "+two+"   \n")
		got, err := loadSSHAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Equal(t, []string{strings.TrimSpace(one), strings.TrimSpace(two)}, got)
	})

	t.Run("a file without a key is an error", func(t *testing.T) {
		_, err := loadSSHAuthorizedKeys(write(t, "# only a comment\n\n"))
		assert.Error(t, err)
	})

	t.Run("a missing file is an error", func(t *testing.T) {
		_, err := loadSSHAuthorizedKeys(filepath.Join(t.TempDir(), "nope"))
		assert.Error(t, err)
	})

	t.Run("a file with a bad key is an error", func(t *testing.T) {
		_, err := loadSSHAuthorizedKeys(write(t, one+"\nnot a key\n"))
		assert.Error(t, err)
	})
}
