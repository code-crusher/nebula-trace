package metrics

import (
	"math"
	"strconv"
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	c := NewCounter()
	if c.Count() != 0 {
		t.Fatalf("expected 0, got %d", c.Count())
	}
	c.Inc(1)
	c.Inc(2)
	if c.Count() != 3 {
		t.Fatalf("expected 3, got %d", c.Count())
	}
	c.Dec(1)
	if c.Count() != 2 {
		t.Fatalf("expected 2, got %d", c.Count())
	}
	c.Clear()
	if c.Count() != 0 {
		t.Fatalf("expected 0 after Clear, got %d", c.Count())
	}
}

func TestNilCounter(t *testing.T) {
	c := NilCounter{}
	c.Inc(1)
	c.Dec(1)
	c.Clear()
	if c.Count() != 0 {
		t.Fatalf("NilCounter.Count must be 0")
	}
}

func TestGauge(t *testing.T) {
	g := NewGauge()
	if g.Value() != 0 {
		t.Fatalf("expected 0, got %d", g.Value())
	}
	g.Update(5)
	if g.Value() != 5 {
		t.Fatalf("expected 5, got %d", g.Value())
	}
	g.Update(-1)
	if g.Value() != -1 {
		t.Fatalf("expected -1, got %d", g.Value())
	}
}

func TestGaugeFloat64(t *testing.T) {
	g := NewGaugeFloat64()
	if g.Value() != 0 {
		t.Fatalf("expected 0, got %f", g.Value())
	}
	g.Update(1.5)
	if g.Value() != 1.5 {
		t.Fatalf("expected 1.5, got %f", g.Value())
	}
	// NaN and Inf must round-trip through the bits
	g.Update(math.NaN())
	if !math.IsNaN(g.Value()) {
		t.Fatalf("expected NaN, got %f", g.Value())
	}
	g.Update(math.Inf(1))
	if !math.IsInf(g.Value(), 1) {
		t.Fatalf("expected +Inf, got %f", g.Value())
	}
}

func TestRegistryGetOrRegister(t *testing.T) {
	r := NewRegistry()
	c1 := GetOrRegisterCounter("a.counter", r)
	c1.Inc(1)
	c2 := GetOrRegisterCounter("a.counter", r)
	if c1 != c2 {
		t.Fatal("GetOrRegisterCounter must return the same instance for the same name")
	}
	if c2.Count() != 1 {
		t.Fatalf("expected 1, got %d", c2.Count())
	}

	// nil registry means the default
	d := GetOrRegisterCounter("default.test", nil)
	d.Inc(1)
	if GetOrRegisterCounter("default.test", nil) != d {
		t.Fatal("nil registry must fall back to DefaultRegistry")
	}
	DefaultRegistry.Unregister("default.test")
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("x", NewCounter()); err != nil {
		t.Fatalf("first Register must succeed: %v", err)
	}
	err := r.Register("x", NewCounter())
	if err == nil {
		t.Fatal("duplicate Register must fail")
	}
	if _, ok := err.(DuplicateMetric); !ok {
		t.Fatalf("expected DuplicateMetric, got %T", err)
	}
}

func TestRegistryEachIsASnapshot(t *testing.T) {
	r := NewRegistry()
	GetOrRegisterCounter("a", r)
	GetOrRegisterGauge("b", r)
	seen := map[string]bool{}
	r.Each(func(name string, _ any) {
		seen[name] = true
		// Unregistering from the callback must not corrupt the iteration
		r.Unregister(name)
	})
	if !seen["a"] || !seen["b"] {
		t.Fatalf("expected to visit a and b, visited %v", seen)
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram(NewExpDecaySample(1028, 0.015))
	for i := int64(1); i <= 1000; i++ {
		h.Update(i)
	}
	if h.Count() != 1000 {
		t.Fatalf("expected count 1000, got %d", h.Count())
	}
	if h.Min() != 1 {
		t.Fatalf("expected min 1, got %d", h.Min())
	}
	if h.Max() != 1000 {
		t.Fatalf("expected max 1000, got %d", h.Max())
	}
	if s := h.Sum(); s != 500500 {
		t.Fatalf("expected sum 500500, got %d", s)
	}
	if m := h.Mean(); m != 500.5 {
		t.Fatalf("expected mean 500.5, got %f", m)
	}
	ps := h.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
	expected := []float64{500.5, 750.75, 950.95, 990.99, 999.999}
	for i, p := range ps {
		if math.Abs(p-expected[i]) > 0.001 {
			t.Fatalf("percentile %d: expected %f, got %f", i, expected[i], p)
		}
	}
	h.Clear()
	if h.Count() != 0 {
		t.Fatalf("expected count 0 after Clear, got %d", h.Count())
	}
}

// Percentiles must not reorder the caller's stored slice: the graphite
// exporter hands the snapshot's values to consecutive percentile calls, and
// sorting in place would race with a concurrent export of the same data.
func TestHistogramPercentilesDoNotSortInput(t *testing.T) {
	s := NewExpDecaySample(1028, 0.015)
	h := NewHistogram(s)
	for i := int64(1); i <= 100; i++ {
		h.Update(i)
	}
	values := s.(*ExpDecaySample).valuesCopy()
	if isSorted(values) {
		t.Fatal("precondition: heap order is not sorted order, pick values that prove it")
	}
	h.Percentiles([]float64{0.99})
	after := s.(*ExpDecaySample).valuesCopy()
	if isSorted(after) {
		t.Fatal("Percentiles must not reorder the reservoir's stored values")
	}
	for i := range values {
		if values[i] != after[i] {
			t.Fatalf("stored values changed at %d: %d != %d", i, values[i], after[i])
		}
	}
}

func isSorted(v []int64) bool {
	for i := 1; i < len(v); i++ {
		if v[i-1] > v[i] {
			return false
		}
	}
	return true
}

// The sample bounds its memory to the reservoir size, dropping the lowest
// priority entries, not the newest.
func TestExpDecaySampleBoundsReservoir(t *testing.T) {
	s := NewExpDecaySample(10, 0.015)
	for i := int64(0); i < 1000; i++ {
		s.Update(i)
	}
	if s.Size() > 10 {
		t.Fatalf("reservoir must stay at most 10, got %d", s.Size())
	}
	if s.Count() != 1000 {
		t.Fatalf("count tracks all updates, expected 1000, got %d", s.Count())
	}
}

func TestTimer(t *testing.T) {
	timer := NewTimer()
	timer.UpdateSince(time.Now().Add(-100 * time.Millisecond))
	if timer.Count() != 1 {
		t.Fatalf("expected count 1, got %d", timer.Count())
	}
	if timer.Min() <= 0 {
		t.Fatalf("expected positive duration, got %d", timer.Min())
	}
	timer.Stop()
}

func TestTimerRates(t *testing.T) {
	timer := NewTimer()
	defer timer.Stop()
	// Rates before any tick are 0; the meter's mean rate is positive as soon
	// as one event is recorded.
	if timer.RateMean() != 0 {
		t.Fatalf("expected mean rate 0 before any event, got %f", timer.RateMean())
	}
	timer.UpdateSince(time.Now())
	// after an update the mean rate is set synchronously
	if timer.RateMean() <= 0 {
		t.Fatalf("expected positive mean rate after an event, got %f", timer.RateMean())
	}
}

func TestMeter(t *testing.T) {
	m := newStandardMeter()
	defer m.Stop()
	m.Mark(10)
	if m.Count() != 10 {
		t.Fatalf("expected 10, got %d", m.Count())
	}
	if m.Rate1() != 0 {
		t.Fatalf("rates stay 0 until the arbiter ticks, got %f", m.Rate1())
	}
	m.tick()
	if m.Rate1() <= 0 {
		t.Fatalf("expected positive rate1 after a tick, got %f", m.Rate1())
	}
}

func TestNilMeter(t *testing.T) {
	m := NilMeter{}
	m.Mark(1)
	m.Stop()
	if m.Count() != 0 || m.Rate1() != 0 || m.Rate5() != 0 || m.Rate15() != 0 || m.RateMean() != 0 {
		t.Fatal("NilMeter must stay zero")
	}
}

func TestRuntimeCapture(t *testing.T) {
	r := NewRegistry()
	RegisterRuntimeMemStats(r)
	RegisterDebugGCStats(r)
	CaptureRuntimeMemStatsOnce(r)
	CaptureDebugGCStatsOnce(r)

	names := map[string]bool{}
	r.Each(func(name string, _ any) { names[name] = true })
	for _, name := range []string{
		"runtime.MemStats.Alloc",
		"runtime.MemStats.NumGC",
		"runtime.NumGoroutine",
		"debug.GCStats.NumGC",
		"debug.ReadGCStats",
	} {
		if !names[name] {
			t.Errorf("expected %s to be registered, have %v", name, names)
		}
	}

	if g := GetOrRegisterGauge("runtime.MemStats.Alloc", r).Value(); g <= 0 {
		t.Errorf("runtime.MemStats.Alloc must be positive after capture, got %d", g)
	}
	if g := GetOrRegisterGauge("runtime.NumGoroutine", r).Value(); g < 1 {
		t.Errorf("runtime.NumGoroutine must be at least 1, got %d", g)
	}
}

func TestDefaultRegistryIsProcessGlobal(t *testing.T) {
	// The stats server hands DefaultRegistry to both exporters; confirm the
	// helpers all agree on it.
	GetOrRegisterCounter("global.test", nil).Inc(3)
	found := false
	DefaultRegistry.Each(func(name string, m any) {
		if name == "global.test" {
			found = true
			if m.(Counter).Count() != 3 {
				t.Errorf("expected 3, got %d", m.(Counter).Count())
			}
		}
	})
	if !found {
		t.Fatal("global.test not in DefaultRegistry")
	}
	DefaultRegistry.Unregister("global.test")
}

func TestGaugeFloat64BitsRoundTrip(t *testing.T) {
	for _, v := range []float64{0, 1, -1, 0.5, math.MaxFloat64, math.SmallestNonzeroFloat64} {
		s := &StandardGaugeFloat64{}
		s.Update(v)
		if s.Value() != v {
			t.Errorf("round trip failed for %f: %s", v, strconv.FormatFloat(s.Value(), 'g', -1, 64))
		}
	}
}
