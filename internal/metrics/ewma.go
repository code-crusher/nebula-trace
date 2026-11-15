package metrics

import (
	"math"
	"sync"
	"sync/atomic"
)

// EWMAs continuously calculate an exponentially-weighted moving average based
// on an outside source of clock ticks.
type EWMA interface {
	Rate() float64
	Tick()
	Update(int64)
}

// StandardEWMA is the standard implementation of an EWMA and tracks the number
// of uncounted events and processes them on each tick.
type StandardEWMA struct {
	uncounted int64 // must be the first member to ensure 64-bit alignment
	alpha     float64
	rate      uint64
	init      uint32
	mutex     sync.Mutex
}

func newEWMA(alpha float64) EWMA {
	return &StandardEWMA{alpha: alpha}
}

// Rate returns the moving average rate of events per second.
func (a *StandardEWMA) Rate() float64 {
	return math.Float64frombits(atomic.LoadUint64(&a.rate)) * float64(1e9)
}

// Tick ticks the clock to update the moving average. It assumes it is called
// every five seconds.
func (a *StandardEWMA) Tick() {
	// Optimization to avoid mutex locking in the hot-path.
	if atomic.LoadUint32(&a.init) == 1 {
		a.updateRate(a.fetchInstantRate())
	} else {
		// Slow-path: this is only needed on the first Tick() and preserves
		// transactional updating of init and rate in the else block. The
		// first conditional is needed below because a different thread could
		// have set a.init = 1 between the time of the first atomic load and
		// when the lock was acquired.
		a.mutex.Lock()
		if atomic.LoadUint32(&a.init) == 1 {
			a.updateRate(a.fetchInstantRate())
		} else {
			atomic.StoreUint32(&a.init, 1)
			atomic.StoreUint64(&a.rate, math.Float64bits(a.fetchInstantRate()))
		}
		a.mutex.Unlock()
	}
}

func (a *StandardEWMA) fetchInstantRate() float64 {
	count := atomic.LoadInt64(&a.uncounted)
	atomic.AddInt64(&a.uncounted, -count)
	instantRate := float64(count) / float64(5e9)
	return instantRate
}

func (a *StandardEWMA) updateRate(instantRate float64) {
	currentRate := math.Float64frombits(atomic.LoadUint64(&a.rate))
	currentRate += a.alpha * (instantRate - currentRate)
	atomic.StoreUint64(&a.rate, math.Float64bits(currentRate))
}

// Update adds n uncounted events.
func (a *StandardEWMA) Update(n int64) {
	atomic.AddInt64(&a.uncounted, n)
}
