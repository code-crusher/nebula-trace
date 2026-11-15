package nebula

// This file is a trimmed, inlined copy of the prometheus provider from
// github.com/nbrownus/go-metrics-prometheus, which has been unmaintained
// since 2021. It was written against the archived github.com/rcrowley/go-metrics
// types (see issue #1590), so it was ported here onto nebula's internal
// metrics package to drop both dependencies. The export shape (one plain
// gauge per counter/gauge, one labeled gauge vector per histogram and timer)
// is unchanged, so existing dashboards keep working.
//
// Copyright 2021 the go-metrics-prometheus authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/slackhq/nebula/internal/metrics"
)

// prometheusProvider mirrors the graphite exporter: it is a point-in-time
// view of the metrics registry, pushed into prometheus gauges. Because
// nebula's metrics are gauges and counters at heart, each registry entry maps
// to one prometheus gauge (or one labeled gauge vector for histograms and
// timers), updated on each capture pass rather than scraped directly.
type prometheusProvider struct {
	namespace     string
	Registry      metrics.Registry // Registry to be exported
	subsystem     string
	promRegistry  prometheus.Registerer
	FlushInterval time.Duration //interval to update prom metrics
	gauges        map[string]prometheus.Gauge
	gaugeVecs     map[string]*prometheus.GaugeVec
}

// newPrometheusProvider returns a provider that produces prometheus metrics
// from the given registry. Namespace and subsystem are applied to all
// produced metrics.
func newPrometheusProvider(r metrics.Registry, namespace string, subsystem string, promRegistry prometheus.Registerer, flushInterval time.Duration) *prometheusProvider {
	return &prometheusProvider{
		namespace:     namespace,
		subsystem:     subsystem,
		Registry:      r,
		promRegistry:  promRegistry,
		FlushInterval: flushInterval,
		gauges:        make(map[string]prometheus.Gauge),
		gaugeVecs:     make(map[string]*prometheus.GaugeVec),
	}
}

func (c *prometheusProvider) flattenKey(key string) string {
	key = strings.Replace(key, " ", "_", -1)
	key = strings.Replace(key, ".", "_", -1)
	key = strings.Replace(key, "-", "_", -1)
	key = strings.Replace(key, "=", "_", -1)
	return key
}

func (c *prometheusProvider) gaugeFromNameAndValue(name string, val float64) {
	key := fmt.Sprintf("%s_%s_%s", c.namespace, c.subsystem, name)
	g, ok := c.gauges[key]
	if !ok {
		g = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: c.flattenKey(c.namespace),
			Subsystem: c.flattenKey(c.subsystem),
			Name:      c.flattenKey(name),
			Help:      name,
		})
		c.promRegistry.MustRegister(g)
		c.gauges[key] = g
	}
	g.Set(val)
}

func (c *prometheusProvider) histogramFromName(name string, h metrics.Histogram) {
	key := fmt.Sprintf("%s_%s_%s", c.namespace, c.subsystem, name)
	g, ok := c.gaugeVecs[key]
	if !ok {
		g = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: c.flattenKey(c.namespace),
			Subsystem: c.flattenKey(c.subsystem),
			Name:      c.flattenKey(name),
			Help:      name,
		},
			[]string{
				"type",
			},
		)
		c.promRegistry.MustRegister(g)
		c.gaugeVecs[key] = g
	}

	g.WithLabelValues("count").Set(float64(h.Count()))
	g.WithLabelValues("max").Set(float64(h.Max()))
	g.WithLabelValues("min").Set(float64(h.Min()))
	g.WithLabelValues("mean").Set(h.Mean())
	g.WithLabelValues("stddev").Set(h.StdDev())
	g.WithLabelValues("perc75").Set(h.Percentile(float64(75)))
	g.WithLabelValues("perc95").Set(h.Percentile(float64(95)))
	g.WithLabelValues("perc99").Set(h.Percentile(float64(99)))
	g.WithLabelValues("perc999").Set(h.Percentile(float64(99.9)))
	g.WithLabelValues("sum").Set(float64(h.Sum()))
	g.WithLabelValues("variance").Set(h.Variance())
}

func (c *prometheusProvider) timerFromName(name string, t metrics.Timer) {
	key := fmt.Sprintf("%s_%s_%s", c.namespace, c.subsystem, name)
	g, ok := c.gaugeVecs[key]
	if !ok {
		g = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: c.flattenKey(c.namespace),
			Subsystem: c.flattenKey(c.subsystem),
			Name:      c.flattenKey(name),
			Help:      name,
		},
			[]string{
				"type",
			},
		)
		c.promRegistry.MustRegister(g)
		c.gaugeVecs[key] = g
	}

	g.WithLabelValues("count").Set(float64(t.Count()))
	g.WithLabelValues("max").Set(float64(t.Max()))
	g.WithLabelValues("min").Set(float64(t.Min()))
	g.WithLabelValues("mean").Set(t.Mean())
	g.WithLabelValues("stddev").Set(t.StdDev())
	g.WithLabelValues("perc75").Set(t.Percentile(float64(75)))
	g.WithLabelValues("perc95").Set(t.Percentile(float64(95)))
	g.WithLabelValues("perc99").Set(t.Percentile(float64(99)))
	g.WithLabelValues("perc999").Set(t.Percentile(float64(99.9)))
	g.WithLabelValues("sum").Set(float64(t.Sum()))
	g.WithLabelValues("variance").Set(t.Variance())

	g.WithLabelValues("rate1").Set(t.Rate1())
	g.WithLabelValues("rate5").Set(t.Rate5())
	g.WithLabelValues("rate15").Set(t.Rate15())
	g.WithLabelValues("rate_mean").Set(t.RateMean())
}

// UpdatePrometheusMetricsOnce iterates the registry and updates each
// corresponding prometheus gauge. It is called from the capture loop, ahead of
// each scrape, so a scrape sees the state of the last capture pass.
func (c *prometheusProvider) UpdatePrometheusMetricsOnce() error {
	c.Registry.Each(func(name string, i any) {
		switch metric := i.(type) {
		case metrics.Counter:
			c.gaugeFromNameAndValue(name, float64(metric.Count()))
		case metrics.Gauge:
			c.gaugeFromNameAndValue(name, float64(metric.Value()))
		case metrics.GaugeFloat64:
			c.gaugeFromNameAndValue(name, metric.Value())
		case metrics.Histogram:
			c.histogramFromName(name, metric)
		case metrics.Timer:
			c.timerFromName(name, metric)
		}
	})
	return nil
}
