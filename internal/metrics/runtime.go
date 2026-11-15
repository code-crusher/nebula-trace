package metrics

import (
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sync"
	"time"
)

// This file carries over the runtime and GC capture helpers from
// github.com/rcrowley/go-metrics (BSD-2, see package comment). Nebula
// registers them once via RegisterRuntimeMemStats/RegisterDebugGCStats and
// then calls the two Capture*Once functions from its own capture loop. The
// only background goroutine is the meter arbiter (see meter.go), started
// when the first capture timer is created and running for the process life,
// exactly as in the original.

var (
	memStats       runtime.MemStats
	runtimeMetrics struct {
		MemStats struct {
			Alloc         Gauge
			BuckHashSys   Gauge
			DebugGC       Gauge
			EnableGC      Gauge
			Frees         Gauge
			HeapAlloc     Gauge
			HeapIdle      Gauge
			HeapInuse     Gauge
			HeapObjects   Gauge
			HeapReleased  Gauge
			HeapSys       Gauge
			LastGC        Gauge
			Lookups       Gauge
			Mallocs       Gauge
			MCacheInuse   Gauge
			MCacheSys     Gauge
			MSpanInuse    Gauge
			MSpanSys      Gauge
			NextGC        Gauge
			NumGC         Gauge
			GCCPUFraction GaugeFloat64
			PauseNs       Histogram
			PauseTotalNs  Gauge
			StackInuse    Gauge
			StackSys      Gauge
			Sys           Gauge
			TotalAlloc    Gauge
		}
		NumCgoCall   Gauge
		NumGoroutine Gauge
		NumThread    Gauge
		ReadMemStats Timer
	}
	frees       uint64
	lookups     uint64
	mallocs     uint64
	numGC       uint32
	numCgoCalls int64

	threadCreateProfile        = pprof.Lookup("threadcreate")
	registerRuntimeMetricsOnce sync.Once
)

// CaptureRuntimeMemStatsOnce captures new values for the Go runtime
// statistics exported in runtime.MemStats. Giving a registry which has not
// been given to RegisterRuntimeMemStats will panic.
//
// Be careful with this because runtime.ReadMemStats stops the world.
func CaptureRuntimeMemStatsOnce(r Registry) {
	t := time.Now()
	runtime.ReadMemStats(&memStats) // This takes 50-200us.
	runtimeMetrics.ReadMemStats.UpdateSince(t)

	runtimeMetrics.MemStats.Alloc.Update(int64(memStats.Alloc))
	runtimeMetrics.MemStats.BuckHashSys.Update(int64(memStats.BuckHashSys))
	if memStats.DebugGC {
		runtimeMetrics.MemStats.DebugGC.Update(1)
	} else {
		runtimeMetrics.MemStats.DebugGC.Update(0)
	}
	if memStats.EnableGC {
		runtimeMetrics.MemStats.EnableGC.Update(1)
	} else {
		runtimeMetrics.MemStats.EnableGC.Update(0)
	}

	runtimeMetrics.MemStats.Frees.Update(int64(memStats.Frees - frees))
	runtimeMetrics.MemStats.HeapAlloc.Update(int64(memStats.HeapAlloc))
	runtimeMetrics.MemStats.HeapIdle.Update(int64(memStats.HeapIdle))
	runtimeMetrics.MemStats.HeapInuse.Update(int64(memStats.HeapInuse))
	runtimeMetrics.MemStats.HeapObjects.Update(int64(memStats.HeapObjects))
	runtimeMetrics.MemStats.HeapReleased.Update(int64(memStats.HeapReleased))
	runtimeMetrics.MemStats.HeapSys.Update(int64(memStats.HeapSys))
	runtimeMetrics.MemStats.LastGC.Update(int64(memStats.LastGC))
	runtimeMetrics.MemStats.Lookups.Update(int64(memStats.Lookups - lookups))
	runtimeMetrics.MemStats.Mallocs.Update(int64(memStats.Mallocs - mallocs))
	runtimeMetrics.MemStats.MCacheInuse.Update(int64(memStats.MCacheInuse))
	runtimeMetrics.MemStats.MCacheSys.Update(int64(memStats.MCacheSys))
	runtimeMetrics.MemStats.MSpanInuse.Update(int64(memStats.MSpanInuse))
	runtimeMetrics.MemStats.MSpanSys.Update(int64(memStats.MSpanSys))
	runtimeMetrics.MemStats.NextGC.Update(int64(memStats.NextGC))
	runtimeMetrics.MemStats.NumGC.Update(int64(memStats.NumGC - numGC))
	runtimeMetrics.MemStats.GCCPUFraction.Update(memStats.GCCPUFraction)

	// https://github.com/golang/go/blob/master/src/runtime/mgc0.c
	i := numGC % uint32(len(memStats.PauseNs))
	ii := memStats.NumGC % uint32(len(memStats.PauseNs))
	if memStats.NumGC-numGC >= uint32(len(memStats.PauseNs)) {
		for i = 0; i < uint32(len(memStats.PauseNs)); i++ {
			runtimeMetrics.MemStats.PauseNs.Update(int64(memStats.PauseNs[i]))
		}
	} else {
		if i > ii {
			for ; i < uint32(len(memStats.PauseNs)); i++ {
				runtimeMetrics.MemStats.PauseNs.Update(int64(memStats.PauseNs[i]))
			}
			i = 0
		}
		for ; i < ii; i++ {
			runtimeMetrics.MemStats.PauseNs.Update(int64(memStats.PauseNs[i]))
		}
	}
	frees = memStats.Frees
	lookups = memStats.Lookups
	mallocs = memStats.Mallocs
	numGC = memStats.NumGC

	runtimeMetrics.MemStats.PauseTotalNs.Update(int64(memStats.PauseTotalNs))
	runtimeMetrics.MemStats.StackInuse.Update(int64(memStats.StackInuse))
	runtimeMetrics.MemStats.StackSys.Update(int64(memStats.StackSys))
	runtimeMetrics.MemStats.Sys.Update(int64(memStats.Sys))
	runtimeMetrics.MemStats.TotalAlloc.Update(int64(memStats.TotalAlloc))

	currentNumCgoCalls := runtime.NumCgoCall()
	runtimeMetrics.NumCgoCall.Update(currentNumCgoCalls - numCgoCalls)
	numCgoCalls = currentNumCgoCalls

	runtimeMetrics.NumGoroutine.Update(int64(runtime.NumGoroutine()))

	runtimeMetrics.NumThread.Update(int64(threadCreateProfile.Count()))
}

// RegisterRuntimeMemStats registers the metrics for the Go runtime statistics
// exported in runtime.MemStats. The metrics are named by their fully-qualified
// Go symbols, i.e. runtime.MemStats.Alloc. The metric objects are constructed
// once per process (the capture functions write to those specific globals),
// but the registration itself runs for every registry passed, mirroring the
// original's discard-the-duplicate-error behavior.
func RegisterRuntimeMemStats(r Registry) {
	registerRuntimeMetricsOnce.Do(func() {
		runtimeMetrics.MemStats.Alloc = NewGauge()
		runtimeMetrics.MemStats.BuckHashSys = NewGauge()
		runtimeMetrics.MemStats.DebugGC = NewGauge()
		runtimeMetrics.MemStats.EnableGC = NewGauge()
		runtimeMetrics.MemStats.Frees = NewGauge()
		runtimeMetrics.MemStats.HeapAlloc = NewGauge()
		runtimeMetrics.MemStats.HeapIdle = NewGauge()
		runtimeMetrics.MemStats.HeapInuse = NewGauge()
		runtimeMetrics.MemStats.HeapObjects = NewGauge()
		runtimeMetrics.MemStats.HeapReleased = NewGauge()
		runtimeMetrics.MemStats.HeapSys = NewGauge()
		runtimeMetrics.MemStats.LastGC = NewGauge()
		runtimeMetrics.MemStats.Lookups = NewGauge()
		runtimeMetrics.MemStats.Mallocs = NewGauge()
		runtimeMetrics.MemStats.MCacheInuse = NewGauge()
		runtimeMetrics.MemStats.MCacheSys = NewGauge()
		runtimeMetrics.MemStats.MSpanInuse = NewGauge()
		runtimeMetrics.MemStats.MSpanSys = NewGauge()
		runtimeMetrics.MemStats.NextGC = NewGauge()
		runtimeMetrics.MemStats.NumGC = NewGauge()
		runtimeMetrics.MemStats.GCCPUFraction = NewGaugeFloat64()
		runtimeMetrics.MemStats.PauseNs = NewHistogram(NewExpDecaySample(1028, 0.015))
		runtimeMetrics.MemStats.PauseTotalNs = NewGauge()
		runtimeMetrics.MemStats.StackInuse = NewGauge()
		runtimeMetrics.MemStats.StackSys = NewGauge()
		runtimeMetrics.MemStats.Sys = NewGauge()
		runtimeMetrics.MemStats.TotalAlloc = NewGauge()
		runtimeMetrics.NumCgoCall = NewGauge()
		runtimeMetrics.NumGoroutine = NewGauge()
		runtimeMetrics.NumThread = NewGauge()
		runtimeMetrics.ReadMemStats = NewTimer()
	})

	// A duplicate registration is not an error to the caller; it means the
	// metric was already registered here.
	_ = r.Register("runtime.MemStats.Alloc", runtimeMetrics.MemStats.Alloc)
	_ = r.Register("runtime.MemStats.BuckHashSys", runtimeMetrics.MemStats.BuckHashSys)
	_ = r.Register("runtime.MemStats.DebugGC", runtimeMetrics.MemStats.DebugGC)
	_ = r.Register("runtime.MemStats.EnableGC", runtimeMetrics.MemStats.EnableGC)
	_ = r.Register("runtime.MemStats.Frees", runtimeMetrics.MemStats.Frees)
	_ = r.Register("runtime.MemStats.HeapAlloc", runtimeMetrics.MemStats.HeapAlloc)
	_ = r.Register("runtime.MemStats.HeapIdle", runtimeMetrics.MemStats.HeapIdle)
	_ = r.Register("runtime.MemStats.HeapInuse", runtimeMetrics.MemStats.HeapInuse)
	_ = r.Register("runtime.MemStats.HeapObjects", runtimeMetrics.MemStats.HeapObjects)
	_ = r.Register("runtime.MemStats.HeapReleased", runtimeMetrics.MemStats.HeapReleased)
	_ = r.Register("runtime.MemStats.HeapSys", runtimeMetrics.MemStats.HeapSys)
	_ = r.Register("runtime.MemStats.LastGC", runtimeMetrics.MemStats.LastGC)
	_ = r.Register("runtime.MemStats.Lookups", runtimeMetrics.MemStats.Lookups)
	_ = r.Register("runtime.MemStats.Mallocs", runtimeMetrics.MemStats.Mallocs)
	_ = r.Register("runtime.MemStats.MCacheInuse", runtimeMetrics.MemStats.MCacheInuse)
	_ = r.Register("runtime.MemStats.MCacheSys", runtimeMetrics.MemStats.MCacheSys)
	_ = r.Register("runtime.MemStats.MSpanInuse", runtimeMetrics.MemStats.MSpanInuse)
	_ = r.Register("runtime.MemStats.MSpanSys", runtimeMetrics.MemStats.MSpanSys)
	_ = r.Register("runtime.MemStats.NextGC", runtimeMetrics.MemStats.NextGC)
	_ = r.Register("runtime.MemStats.NumGC", runtimeMetrics.MemStats.NumGC)
	_ = r.Register("runtime.MemStats.GCCPUFraction", runtimeMetrics.MemStats.GCCPUFraction)
	_ = r.Register("runtime.MemStats.PauseNs", runtimeMetrics.MemStats.PauseNs)
	_ = r.Register("runtime.MemStats.PauseTotalNs", runtimeMetrics.MemStats.PauseTotalNs)
	_ = r.Register("runtime.MemStats.StackInuse", runtimeMetrics.MemStats.StackInuse)
	_ = r.Register("runtime.MemStats.StackSys", runtimeMetrics.MemStats.StackSys)
	_ = r.Register("runtime.MemStats.Sys", runtimeMetrics.MemStats.Sys)
	_ = r.Register("runtime.MemStats.TotalAlloc", runtimeMetrics.MemStats.TotalAlloc)
	_ = r.Register("runtime.NumCgoCall", runtimeMetrics.NumCgoCall)
	_ = r.Register("runtime.NumGoroutine", runtimeMetrics.NumGoroutine)
	_ = r.Register("runtime.NumThread", runtimeMetrics.NumThread)
	_ = r.Register("runtime.ReadMemStats", runtimeMetrics.ReadMemStats)
}

var (
	debugMetrics struct {
		GCStats struct {
			LastGC     Gauge
			NumGC      Gauge
			Pause      Histogram
			PauseTotal Gauge
		}
		ReadGCStats Timer
	}
	gcStats                  debug.GCStats
	registerDebugMetricsOnce sync.Once
)

// Allocate an initial slice for gcStats.Pause to avoid allocations during
// normal operation, as in the original.
func init() {
	gcStats.Pause = make([]time.Duration, 11)
}

// CaptureDebugGCStatsOnce captures new values for the Go garbage collector
// statistics exported in debug.GCStats. Giving a registry which has not been
// given to RegisterDebugGCStats will panic.
func CaptureDebugGCStatsOnce(r Registry) {
	lastGC := gcStats.LastGC
	t := time.Now()
	debug.ReadGCStats(&gcStats)
	debugMetrics.ReadGCStats.UpdateSince(t)

	debugMetrics.GCStats.LastGC.Update(int64(gcStats.LastGC.UnixNano()))
	debugMetrics.GCStats.NumGC.Update(int64(gcStats.NumGC))
	if lastGC != gcStats.LastGC && 0 < len(gcStats.Pause) {
		debugMetrics.GCStats.Pause.Update(int64(gcStats.Pause[0]))
	}
	debugMetrics.GCStats.PauseTotal.Update(int64(gcStats.PauseTotal))
}

// RegisterDebugGCStats registers the metrics for the Go garbage collector
// statistics exported in debug.GCStats. The metrics are named by their
// fully-qualified Go symbols, i.e. debug.GCStats.PauseTotal. The metric
// objects are constructed once per process, but the registration itself runs
// for every registry passed; a duplicate is not an error to the caller.
func RegisterDebugGCStats(r Registry) {
	registerDebugMetricsOnce.Do(func() {
		debugMetrics.GCStats.LastGC = NewGauge()
		debugMetrics.GCStats.NumGC = NewGauge()
		debugMetrics.GCStats.Pause = NewHistogram(NewExpDecaySample(1028, 0.015))
		debugMetrics.GCStats.PauseTotal = NewGauge()
		debugMetrics.ReadGCStats = NewTimer()
	})

	_ = r.Register("debug.GCStats.LastGC", debugMetrics.GCStats.LastGC)
	_ = r.Register("debug.GCStats.NumGC", debugMetrics.GCStats.NumGC)
	_ = r.Register("debug.GCStats.Pause", debugMetrics.GCStats.Pause)
	_ = r.Register("debug.GCStats.PauseTotal", debugMetrics.GCStats.PauseTotal)
	_ = r.Register("debug.ReadGCStats", debugMetrics.ReadGCStats)
}

// Timer records the duration and rate of events. Only the two timers the
// original library registers (runtime.ReadMemStats, debug.ReadGCStats) ever
// exist: they time the capture calls themselves. The original Timer also kept
// a Meter for one-, five-, and fifteen-minute rates, which the graphite
// exporter emits, so that is kept too.
type Timer interface {
	Count() int64
	Max() int64
	Mean() float64
	Min() int64
	Percentile(float64) float64
	Percentiles([]float64) []float64
	Rate1() float64
	Rate5() float64
	Rate15() float64
	RateMean() float64
	StdDev() float64
	Stop()
	Sum() int64
	UpdateSince(time.Time)
	Variance() float64
}

// standardTimer is the standard implementation of a Timer and uses a
// Histogram and a Meter.
type standardTimer struct {
	histogram Histogram
	meter     Meter
	mutex     sync.Mutex
}

// NewTimer constructs a new Timer backed by an exponentially-decaying sample
// with the same reservoir size and alpha as UNIX load averages, and a meter
// ticked by the package arbiter, as in the original.
func NewTimer() Timer {
	m := newStandardMeter()
	arbiter.Lock()
	arbiter.meters[m] = struct{}{}
	if !arbiter.started {
		arbiter.started = true
		go arbiter.loop()
	}
	arbiter.Unlock()
	return &standardTimer{
		histogram: NewHistogram(NewExpDecaySample(1028, 0.015)),
		meter:     m,
	}
}

// Count returns the number of events recorded.
func (t *standardTimer) Count() int64 { return t.histogram.Count() }

// Max returns the maximum value in the sample.
func (t *standardTimer) Max() int64 { return t.histogram.Max() }

// Mean returns the mean of the values in the sample.
func (t *standardTimer) Mean() float64 { return t.histogram.Mean() }

// Min returns the minimum value in the sample.
func (t *standardTimer) Min() int64 { return t.histogram.Min() }

// Percentile returns an arbitrary percentile of the values in the sample.
func (t *standardTimer) Percentile(p float64) float64 { return t.histogram.Percentile(p) }

// Percentiles returns a slice of arbitrary percentiles of the values in the
// sample.
func (t *standardTimer) Percentiles(ps []float64) []float64 {
	return t.histogram.Percentiles(ps)
}

// Rate1 returns the one-minute moving average rate of events per second.
func (t *standardTimer) Rate1() float64 { return t.meter.Rate1() }

// Rate5 returns the five-minute moving average rate of events per second.
func (t *standardTimer) Rate5() float64 { return t.meter.Rate5() }

// Rate15 returns the fifteen-minute moving average rate of events per second.
func (t *standardTimer) Rate15() float64 { return t.meter.Rate15() }

// RateMean returns the meter's mean rate of events per second.
func (t *standardTimer) RateMean() float64 { return t.meter.RateMean() }

// StdDev returns the standard deviation of the values in the sample.
func (t *standardTimer) StdDev() float64 { return t.histogram.StdDev() }

// Stop stops the meter.
func (t *standardTimer) Stop() { t.meter.Stop() }

// Sum returns the sum in the sample.
func (t *standardTimer) Sum() int64 { return t.histogram.Sum() }

// UpdateSince records the duration of an event that started at a time and
// ends now.
func (t *standardTimer) UpdateSince(ts time.Time) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.histogram.Update(int64(time.Since(ts)))
	t.meter.Mark(1)
}

// Variance returns the variance of the values in the sample.
func (t *standardTimer) Variance() float64 { return t.histogram.Variance() }
