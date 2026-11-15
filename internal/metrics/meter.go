package metrics

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Meters count events to produce exponentially-weighted moving average rates
// at one-, five-, and fifteen-minutes and a mean rate.
type Meter interface {
	Count() int64
	Mark(int64)
	Rate1() float64
	Rate5() float64
	Rate15() float64
	RateMean() float64
	Stop()
}

// StandardMeter is the standard implementation of a Meter.
type StandardMeter struct {
	snapshot    *meterSnapshot
	a1, a5, a15 EWMA
	startTime   time.Time
	stopped     uint32
}

func newStandardMeter() *StandardMeter {
	return &StandardMeter{
		snapshot:  &meterSnapshot{},
		a1:        newEWMA(1 - math.Exp(-5.0/60.0/1)),
		a5:        newEWMA(1 - math.Exp(-5.0/60.0/5)),
		a15:       newEWMA(1 - math.Exp(-5.0/60.0/15)),
		startTime: time.Now(),
	}
}

// Stop stops the meter: the arbiter stops ticking it and Mark becomes a no-op.
func (m *StandardMeter) Stop() {
	if atomic.CompareAndSwapUint32(&m.stopped, 0, 1) {
		arbiter.Lock()
		delete(arbiter.meters, m)
		arbiter.Unlock()
	}
}

// Count returns the number of events recorded.
func (m *StandardMeter) Count() int64 {
	return atomic.LoadInt64(&m.snapshot.count)
}

// Mark records the occurrence of n events.
func (m *StandardMeter) Mark(n int64) {
	if atomic.LoadUint32(&m.stopped) == 1 {
		return
	}

	atomic.AddInt64(&m.snapshot.count, n)

	m.a1.Update(n)
	m.a5.Update(n)
	m.a15.Update(n)
	m.updateSnapshot()
}

// Rate1 returns the one-minute moving average rate of events per second.
func (m *StandardMeter) Rate1() float64 {
	return math.Float64frombits(atomic.LoadUint64(&m.snapshot.rate1))
}

// Rate5 returns the five-minute moving average rate of events per second.
func (m *StandardMeter) Rate5() float64 {
	return math.Float64frombits(atomic.LoadUint64(&m.snapshot.rate5))
}

// Rate15 returns the fifteen-minute moving average rate of events per second.
func (m *StandardMeter) Rate15() float64 {
	return math.Float64frombits(atomic.LoadUint64(&m.snapshot.rate15))
}

// RateMean returns the meter's mean rate of events per second.
func (m *StandardMeter) RateMean() float64 {
	return math.Float64frombits(atomic.LoadUint64(&m.snapshot.rateMean))
}

func (m *StandardMeter) updateSnapshot() {
	rate1 := math.Float64bits(m.a1.Rate())
	rate5 := math.Float64bits(m.a5.Rate())
	rate15 := math.Float64bits(m.a15.Rate())
	rateMean := math.Float64bits(float64(m.Count()) / time.Since(m.startTime).Seconds())

	atomic.StoreUint64(&m.snapshot.rate1, rate1)
	atomic.StoreUint64(&m.snapshot.rate5, rate5)
	atomic.StoreUint64(&m.snapshot.rate15, rate15)
	atomic.StoreUint64(&m.snapshot.rateMean, rateMean)
}

func (m *StandardMeter) tick() {
	m.a1.Tick()
	m.a5.Tick()
	m.a15.Tick()
	m.updateSnapshot()
}

// meterSnapshot is the atomically-updated read view of a StandardMeter.
type meterSnapshot struct {
	count                          int64
	rate1, rate5, rate15, rateMean uint64
}

// meterArbiter ticks meters every 5s from a single goroutine, started lazily
// on first meter creation and running for the life of the process, as in the
// original. Only the capture timers ever create meters, so in nebula it only
// runs while stats are enabled.
type meterArbiter struct {
	sync.RWMutex
	started bool
	meters  map[*StandardMeter]struct{}
	ticker  *time.Ticker
}

var arbiter = meterArbiter{ticker: time.NewTicker(5 * time.Second), meters: make(map[*StandardMeter]struct{})}

// loop ticks meters on the scheduled interval for the life of the process,
// exactly as the original's arbiter goroutine does.
func (ma *meterArbiter) loop() {
	for {
		select {
		case <-ma.ticker.C:
			ma.tickMeters()
		}
	}
}

func (ma *meterArbiter) tickMeters() {
	ma.RLock()
	defer ma.RUnlock()
	for meter := range ma.meters {
		meter.tick()
	}
}

// NilMeter is a no-op Meter.
type NilMeter struct{}

// Count is a no-op.
func (NilMeter) Count() int64 { return 0 }

// Mark is a no-op.
func (NilMeter) Mark(n int64) {}

// Rate1 is a no-op.
func (NilMeter) Rate1() float64 { return 0.0 }

// Rate5 is a no-op.
func (NilMeter) Rate5() float64 { return 0.0 }

// Rate15 is a no-op.
func (NilMeter) Rate15() float64 { return 0.0 }

// RateMean is a no-op.
func (NilMeter) RateMean() float64 { return 0.0 }

// Stop is a no-op.
func (NilMeter) Stop() {}
