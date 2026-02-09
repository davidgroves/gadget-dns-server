package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "gadget_dns"

var (
	// DNSQueriesTotal is the total number of DNS queries received, by transport, qtype, and rcode.
	DNSQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "queries_total",
			Help:      "Total number of DNS queries received",
		},
		[]string{"transport", "qtype", "rcode"},
	)

	// DNSRequestDurationSeconds is the latency of DNS request handling.
	DNSRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "DNS request handling duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"transport"},
	)
)

// Recorder records DNS request metrics for Prometheus.
type Recorder interface {
	RecordDNS(transport, qtype, rcode string, duration time.Duration)
}

// recorder implements Recorder using the default Prometheus registry.
type recorder struct{}

// NewRecorder returns a Recorder that updates application Prometheus metrics.
func NewRecorder() Recorder {
	return &recorder{}
}

// RecordDNS increments query count and observes duration.
func (r *recorder) RecordDNS(transport, qtype, rcode string, duration time.Duration) {
	DNSQueriesTotal.WithLabelValues(transport, qtype, rcode).Inc()
	DNSRequestDurationSeconds.WithLabelValues(transport).Observe(duration.Seconds())
}
