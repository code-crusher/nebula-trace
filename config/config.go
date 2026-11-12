package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dario.cat/mergo"
	"go.yaml.in/yaml/v3"
)

type C struct {
	path     string
	files    []string
	Settings map[string]any
	// runSettings is the last config that loaded and applied cleanly, what a reload diffs a key against to decide if
	// it changed. It only advances when nothing failed, so a reload that fails partway is retried in full by the next
	// one. Guarded by reloadLock
	runSettings map[string]any
	// startupSettings is the config the process booted with, set the first time a load happens. RestartRequiredIfChanged
	// diffs against it, because a key that only applies on a restart is running its startup value for the life of
	// the process. Guarded by reloadLock
	startupSettings map[string]any
	callbacks       []func(*C, *Reload)
	l              *slog.Logger
	reloadLock     sync.Mutex

	// The keys that only apply on a restart and differ from what nebula is running, as the last reload that ran its
	// callbacks found them. A later reload re-decides each one, so a key that is reverted drops out. Guarded by
	// reloadLock
	restartKeys []string

	// needsRestart is the last reload's verdict on whether a restart is required, kept so a reload whose config does
	// not load, and so cannot re-decide, still reports it. It covers the restarts that name no key, like a new cert
	// that changes our networks. Guarded by reloadLock
	needsRestart bool

	// callbackLock guards callbacks. Registration is not confined to startup: CatchHUP is
	// running from inside Main, and anything wired up after Main returns registers while
	// a HUP could already be reloading, so append and iteration have to be serialized.
	callbackLock sync.Mutex
}

func NewC(l *slog.Logger) *C {
	return &C{
		Settings: make(map[string]any),
		l:        l,
	}
}

// Load will find all yaml files within path and load them in lexical order
func (c *C) Load(path string) error {
	c.path = path
	c.files = make([]string, 0)

	err := c.resolve(path, true)
	if err != nil {
		return err
	}

	if len(c.files) == 0 {
		return fmt.Errorf("no config files found at %s", path)
	}

	sort.Strings(c.files)

	err = c.parse()
	if err != nil {
		return err
	}

	return nil
}

func (c *C) LoadString(raw string) error {
	if raw == "" {
		return errors.New("Empty configuration")
	}
	return c.parseRaw([]byte(raw))
}

// RegisterReloadCallback stores a function to be called when a config reload is triggered. The functions registered
// here should decide if they need to make a change to the current process before making the change. HasChanged can be
// used to help decide if a change is necessary.
// These functions should return quickly or spawn their own go routine if they will take a while.
// Use r to report anything that failed or needs a restart to apply.
func (c *C) RegisterReloadCallback(f func(c *C, r *Reload)) {
	c.callbackLock.Lock()
	defer c.callbackLock.Unlock()
	c.callbacks = append(c.callbacks, f)
}

// reloadCallbacks returns a snapshot of the registered callbacks. Reloads iterate the
// snapshot rather than the live slice, so a registration from another goroutine cannot
// race the loop; a callback registered while a reload is in progress runs from the next
// reload on. callbackLock is not held during the calls themselves, so a callback that
// registers another callback does not deadlock.
func (c *C) reloadCallbacks() []func(*C, *Reload) {
	c.callbackLock.Lock()
	defer c.callbackLock.Unlock()
	return append(make([]func(*C, *Reload), 0, len(c.callbacks)), c.callbacks...)
}

// InitialLoad returns true if this is the first load of the config, and ReloadConfig has not been called yet.
func (c *C) InitialLoad() bool {
	return c.startupSettings == nil
}

// Render returns keys and their values as yaml, for a subsystem to remember what it applied. Empty means they couldn't
// be rendered and should never match.
func (c *C) Render(keys ...string) string {
	m := make(map[string]any, len(keys))
	for _, k := range keys {
		m[k] = c.Get(k)
	}
	b, err := yaml.Marshal(m)
	if err != nil {
		c.l.Debug("Failed to render config", "keys", keys, "error", err)
		return ""
	}
	return string(b)
}

// HasChanged checks if the underlying structure of the provided key has changed after a config reload. The value of
// k in the last config that applied cleanly and the new settings will be serialized, the result of the string
// comparison is returned. If k is an empty string the entire config is tested.
// It's important to note that this is very rudimentary and susceptible to configuration ordering issues indicating
// there is change when there actually wasn't any.
func (c *C) HasChanged(k string) bool {
	return c.hasChanged(k, c.runSettings)
}

// HasChangedSinceStartup is HasChanged against the config the process started with, which is what a key that only
// applies on a restart keeps running until the process restarts.
func (c *C) HasChangedSinceStartup(k string) bool {
	return c.hasChanged(k, c.startupSettings)
}

func (c *C) hasChanged(k string, from map[string]any) bool {
	if c.InitialLoad() {
		return false
	}

	var (
		nv any
		ov any
	)

	if k == "" {
		nv = c.Settings
		ov = from
		k = "all settings"
	} else {
		nv = c.get(k, c.Settings)
		ov = c.get(k, from)
	}

	// A scalar is compared the way the getters read it, as a string. A quoted int in one config and a bare one in
	// the other is the same value to nebula, and yaml would marshal the two differently
	if nv == nil || ov == nil {
		return nv != ov
	}
	if _, ok := nv.(map[string]any); !ok {
		if _, ok := nv.([]any); !ok {
			nv = fmt.Sprintf("%v", nv)
			ov = fmt.Sprintf("%v", ov)
		}
	}

	newVals, err := yaml.Marshal(nv)
	if err != nil {
		c.l.Error("Error while marshaling new config",
			"config_path", k,
			"error", err,
		)
	}

	oldVals, err := yaml.Marshal(ov)
	if err != nil {
		c.l.Error("Error while marshaling old config",
			"config_path", k,
			"error", err,
		)
	}

	return string(newVals) != string(oldVals)
}

// CatchHUP will listen for the HUP signal in a go routine and reload all configs found in the
// original path provided to Load.
func (c *C) CatchHUP(ctx context.Context) {
	if c.path == "" {
		return
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(ch)
				close(ch)
				return
			case <-ch:
				c.l.Info("Caught HUP, reloading config")
				c.ReloadConfig().Log(c.l)
			}
		}
	}()
}

// ReloadConfig reloads the config from the path provided to Load and runs every registered callback. A config that
// fails to load is logged here, like any other failure, and the result carries the error for the summary.
func (c *C) ReloadConfig() ReloadResult {
	return c.reload(func() error { return c.Load(c.path) }, "config_path", c.path)
}

// ReloadConfigString is ReloadConfig for a config held in memory rather than on disk.
func (c *C) ReloadConfigString(raw string) ReloadResult {
	return c.reload(func() error { return c.LoadString(raw) }, "", nil)
}

// reload runs load and then the callbacks, and assembles the result. load failing is logged, like any other failure,
// and the result carries the error for the summary. logKey is only for the log line.
func (c *C) reload(load func() error, logKey string, logValue any) ReloadResult {
	c.reloadLock.Lock()
	defer c.reloadLock.Unlock()

	// What is running before this reload: the startup config if no reload has applied yet, otherwise what the last
	// reload that applied cleanly left behind
	running := c.Settings

	if err := load(); err != nil {
		if logKey != "" {
			c.l.Error("Error occurred while reloading config", logKey, logValue, "error", err)
		} else {
			c.l.Error("Error occurred while reloading config", "error", err)
		}
		// Nothing was applied, so the verdict the last reload that ran its callbacks reached still stands
		return ReloadResult{Err: err, RestartRequired: c.needsRestart, RestartKeys: c.restartKeys}
	}

	if c.startupSettings == nil {
		c.startupSettings = make(map[string]any)
		maps.Copy(c.startupSettings, running)
		c.runSettings = make(map[string]any)
		maps.Copy(c.runSettings, running)
	}

	r := &Reload{c: c}
	for _, v := range c.reloadCallbacks() {
		v(c, r)
	}

	// RestartRequiredIfChanged re-decides every key against what nebula is running, so this is the complete set:
	// a reload that reverts a key drops it, one that changes nothing lists whatever still differs
	c.restartKeys = r.keys
	c.needsRestart = r.restart || len(r.keys) > 0

	// What a reload diffs against only advances when nothing failed, so a reload that fails partway is retried in
	// full by the next one rather than reporting that nothing changed
	if !r.failed {
		c.runSettings = make(map[string]any)
		maps.Copy(c.runSettings, c.Settings)
	}

	return ReloadResult{Failed: r.failed, RestartRequired: c.needsRestart, RestartKeys: r.keys}
}

// GetString will get the string for k or return the default d if not found or invalid
func (c *C) GetString(k, d string) string {
	r := c.Get(k)
	if r == nil {
		return d
	}

	return fmt.Sprintf("%v", r)
}

// GetStringSlice will get the slice of strings for k or return the default d if not found or invalid
func (c *C) GetStringSlice(k string, d []string) []string {
	r := c.Get(k)
	if r == nil {
		return d
	}

	rv, ok := r.([]any)
	if !ok {
		return d
	}

	v := make([]string, len(rv))
	for i := range v {
		v[i] = fmt.Sprintf("%v", rv[i])
	}

	return v
}

// GetStringSliceStrict gets the slice of strings for k, or nil if k is not
// set. Unlike GetStringSlice, a value that is set but is not a list is an
// error rather than the default, so a one entry list written without its
// leading dash is reported instead of read as empty.
func (c *C) GetStringSliceStrict(k string) ([]string, error) {
	r := c.Get(k)
	if r == nil {
		return nil, nil
	}

	rv, ok := r.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list, but wasn't: %v", k, r)
	}

	v := make([]string, len(rv))
	for i := range v {
		v[i] = fmt.Sprintf("%v", rv[i])
	}

	return v, nil
}

// GetMap will get the map for k or return the default d if not found or invalid
func (c *C) GetMap(k string, d map[string]any) map[string]any {
	r := c.Get(k)
	if r == nil {
		return d
	}

	v, ok := r.(map[string]any)
	if !ok {
		return d
	}

	return v
}

// GetInt will get the int for k or return the default d if not found or invalid
func (c *C) GetInt(k string, d int) int {
	r := c.GetString(k, strconv.Itoa(d))
	v, err := strconv.Atoi(r)
	if err != nil {
		return d
	}

	return v
}

// GetUint32 will get the uint32 for k or return the default d if not found or invalid
func (c *C) GetUint32(k string, d uint32) uint32 {
	r := c.GetInt(k, int(d))
	if r < 0 || uint64(r) > uint64(math.MaxUint32) {
		return d
	}
	return uint32(r)
}

// GetBool will get the bool for k or return the default d if not found or invalid
func (c *C) GetBool(k string, d bool) bool {
	r := strings.ToLower(c.GetString(k, fmt.Sprintf("%v", d)))
	v, err := strconv.ParseBool(r)
	if err != nil {
		switch r {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		return d
	}

	return v
}

func AsBool(v any) (value bool, ok bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch x {
		case "y", "yes":
			return true, true
		case "n", "no":
			return false, true
		}
	}

	return false, false
}

// GetDuration will get the duration for k or return the default d if not found or invalid
func (c *C) GetDuration(k string, d time.Duration) time.Duration {
	r := c.GetString(k, "")
	v, err := time.ParseDuration(r)
	if err != nil {
		return d
	}
	return v
}

func (c *C) Get(k string) any {
	return c.get(k, c.Settings)
}

func (c *C) IsSet(k string) bool {
	return c.get(k, c.Settings) != nil
}

func (c *C) get(k string, v any) any {
	parts := strings.SplitSeq(k, ".")
	for p := range parts {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}

		v, ok = m[p]
		if !ok {
			return nil
		}
	}

	return v
}

// direct signifies if this is the config path directly specified by the user,
// versus a file/dir found by recursing into that path
func (c *C) resolve(path string, direct bool) error {
	i, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if !i.IsDir() {
		c.addFile(path, direct)
		return nil
	}

	paths, err := readDirNames(path)
	if err != nil {
		return fmt.Errorf("problem while reading directory %s: %s", path, err)
	}

	for _, p := range paths {
		err := c.resolve(filepath.Join(path, p), false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *C) addFile(path string, direct bool) error {
	ext := filepath.Ext(path)

	if !direct && ext != ".yaml" && ext != ".yml" {
		return nil
	}

	ap, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	c.files = append(c.files, ap)
	return nil
}

func (c *C) parseRaw(b []byte) error {
	var m map[string]any

	err := yaml.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	c.Settings = m
	return nil
}

func (c *C) parse() error {
	var m map[string]any

	for _, path := range c.files {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var nm map[string]any
		err = yaml.Unmarshal(b, &nm)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		// We need to use WithAppendSlice so that firewall rules in separate
		// files are appended together
		err = mergo.Merge(&nm, m, mergo.WithAppendSlice)
		m = nm
		if err != nil {
			return err
		}
	}

	c.Settings = m
	return nil
}

func readDirNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	paths, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}

	sort.Strings(paths)
	return paths, nil
}
