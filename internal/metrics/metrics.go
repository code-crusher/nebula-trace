// Package metrics is an in-tree replacement for the archived
// github.com/rcrowley/go-metrics (archived April 2025, see issue #1590). It
// provides exactly the pieces Nebula uses: a name-keyed registry of counters,
// gauges, and histograms backed by an exponentially-decaying sample, plus
// runtime and GC capture helpers. The API mirrors the original so call sites
// keep their shape, and the algorithms (forward-decay reservoir sampling, the
// meter's EWMA rates) are carried over from the original, which is BSD-2
// licensed:
//
// Copyright 2012 Richard Crowley. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//  1. Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY RICHARD CROWLEY “AS IS” AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL RICHARD CROWLEY OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
package metrics

import (
	"math"
	"sync/atomic"
)

// Counter holds an int64 value that can be incremented and decremented.
type Counter interface {
	Clear()
	Count() int64
	Dec(int64)
	Inc(int64)
}

// Gauge holds an int64 value that can be set arbitrarily.
type Gauge interface {
	Update(int64)
	Value() int64
}

// GaugeFloat64 holds a float64 value that can be set arbitrarily.
type GaugeFloat64 interface {
	Update(float64)
	Value() float64
}

// StandardCounter is the standard implementation of a Counter.
type StandardCounter struct {
	n int64
}

// Clear sets the counter to zero.
func (c *StandardCounter) Clear() { atomic.StoreInt64(&c.n, 0) }

// Count returns the counter's current value.
func (c *StandardCounter) Count() int64 { return atomic.LoadInt64(&c.n) }

// Dec decrements the counter by the given amount.
func (c *StandardCounter) Dec(i int64) { atomic.AddInt64(&c.n, -i) }

// Inc increments the counter by the given amount.
func (c *StandardCounter) Inc(i int64) { atomic.AddInt64(&c.n, i) }

// NilCounter is a no-op Counter.
type NilCounter struct{}

// Clear is a no-op.
func (NilCounter) Clear() {}

// Count is a no-op.
func (NilCounter) Count() int64 { return 0 }

// Dec is a no-op.
func (NilCounter) Dec(i int64) {}

// Inc is a no-op.
func (NilCounter) Inc(i int64) {}

// NewCounter constructs a new StandardCounter.
func NewCounter() Counter { return &StandardCounter{} }

// StandardGauge is the standard implementation of a Gauge.
type StandardGauge struct {
	value atomic.Int64
}

// Update sets the gauge's value.
func (g *StandardGauge) Update(v int64) { g.value.Store(v) }

// Value returns the gauge's current value.
func (g *StandardGauge) Value() int64 { return g.value.Load() }

// NewGauge constructs a new StandardGauge.
func NewGauge() Gauge { return &StandardGauge{} }

// StandardGaugeFloat64 is the standard implementation of a GaugeFloat64. The
// value is stored in an atomic.Uint64 holding math.Float64bits.
type StandardGaugeFloat64 struct {
	value atomic.Uint64
}

// Update sets the gauge's value.
func (g *StandardGaugeFloat64) Update(v float64) { g.value.Store(math.Float64bits(v)) }

// Value returns the gauge's current value.
func (g *StandardGaugeFloat64) Value() float64 { return math.Float64frombits(g.value.Load()) }

// NewGaugeFloat64 constructs a new StandardGaugeFloat64.
func NewGaugeFloat64() GaugeFloat64 { return &StandardGaugeFloat64{} }
