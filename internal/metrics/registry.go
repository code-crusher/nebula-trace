package metrics

import (
	"sync"
)

// A Registry holds references to a set of metrics by name. Metrics are
// registered under their fully-qualified name (e.g. "runtime.MemStats.Alloc")
// and iterated in map order.
type Registry interface {
	// Call the given function for each registered metric.
	Each(func(name string, metric any))

	// Gets an existing metric or constructs, registers, and returns a new one
	// via the supplied function.
	GetOrRegister(name string, newMetric func() any) any

	// Register the given metric under the given name. Returns an error if a
	// metric by that name is already registered.
	Register(name string, metric any) error

	// Unregister the metric with the given name.
	Unregister(name string)

	// Unregister all metrics.
	UnregisterAll()
}

// StandardRegistry is the standard implementation of a Registry: a
// mutex-protected map of names to metrics.
type StandardRegistry struct {
	metrics map[string]any
	mutex   sync.RWMutex
}

// NewRegistry creates a new registry.
func NewRegistry() Registry {
	return &StandardRegistry{metrics: make(map[string]any)}
}

// Each calls the given function for each registered metric, holding no lock
// while it runs. The visit set is a snapshot taken under the read lock, so
// unregistering from the callback doesn't corrupt the iteration (the metric
// may still be visited).
func (r *StandardRegistry) Each(f func(name string, metric any)) {
	r.mutex.RLock()
	registered := make([]struct {
		name   string
		metric any
	}, 0, len(r.metrics))
	for name, metric := range r.metrics {
		registered = append(registered, struct {
			name   string
			metric any
		}{name, metric})
	}
	r.mutex.RUnlock()
	for _, kv := range registered {
		f(kv.name, kv.metric)
	}
}

// GetOrRegister gets an existing metric or constructs, registers, and returns
// a new one via the supplied function.
func (r *StandardRegistry) GetOrRegister(name string, newMetric func() any) any {
	r.mutex.RLock()
	metric, ok := r.metrics[name]
	r.mutex.RUnlock()
	if ok {
		return metric
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	if metric, ok := r.metrics[name]; ok {
		return metric
	}
	metric = newMetric()
	r.metrics[name] = metric
	return metric
}

// Register registers the given metric under the given name, returning an
// error if one is already registered under that name.
func (r *StandardRegistry) Register(name string, metric any) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if _, ok := r.metrics[name]; ok {
		return DuplicateMetric(name)
	}
	r.metrics[name] = metric
	return nil
}

// Unregister removes the metric with the given name, if any.
func (r *StandardRegistry) Unregister(name string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.metrics, name)
}

// UnregisterAll removes all metrics, including the capture-registered runtime
// and GC metrics.
func (r *StandardRegistry) UnregisterAll() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metrics = make(map[string]any)
}

// DuplicateMetric is the error returned by Registry.Register when a metric
// already exists.
type DuplicateMetric string

// Error returns the error message.
func (err DuplicateMetric) Error() string {
	return "duplicate metric: " + string(err)
}

// DefaultRegistry is the registry used by the GetOrRegister* helpers when
// passed a nil registry. It is process-global, like the original
// go-metrics's DefaultRegistry.
var DefaultRegistry Registry = NewRegistry()

// GetOrRegisterCounter returns an existing Counter or constructs and registers
// a new StandardCounter.
func GetOrRegisterCounter(name string, r Registry) Counter {
	if r == nil {
		r = DefaultRegistry
	}
	return r.GetOrRegister(name, func() any { return NewCounter() }).(Counter)
}

// GetOrRegisterGauge returns an existing Gauge or constructs and registers a
// new StandardGauge.
func GetOrRegisterGauge(name string, r Registry) Gauge {
	if r == nil {
		r = DefaultRegistry
	}
	return r.GetOrRegister(name, func() any { return NewGauge() }).(Gauge)
}

// GetOrRegisterHistogram returns an existing Histogram or constructs and
// registers a new StandardHistogram backed by s.
func GetOrRegisterHistogram(name string, r Registry, s Sample) Histogram {
	if r == nil {
		r = DefaultRegistry
	}
	return r.GetOrRegister(name, func() any { return NewHistogram(s) }).(Histogram)
}
