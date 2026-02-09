package httpapi

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EntropySample is one recorded DNS query for entropy (port, transaction ID, QNAME for 0x20).
type EntropySample struct {
	SourcePort    int
	TransactionID uint16
	Qname         string // QNAME as received (for 0x20 case variability)
	At            time.Time
}

// EntropyRun holds samples for one run and optional cached result.
type EntropyRun struct {
	Samples   []EntropySample
	Result    *EntropyResult
	ResultN   int // N used to compute Result (0 = not computed)
	CreatedAt time.Time
}

// EntropyResult is the computed port/ID entropy and ratings for a run.
type EntropyResult struct {
	PortStddev          float64  `json:"port_stddev"`
	IDStddev            float64  `json:"id_stddev"`
	PortChi2            float64  `json:"port_chi2"` // chi-squared uniformity (256 buckets, df=255)
	IDChi2              float64  `json:"id_chi2"`   // chi-squared uniformity (256 buckets, df=255)
	PortRating          string   `json:"port_rating"`
	IDRating            string   `json:"id_rating"`
	SamplesCount        int      `json:"samples_count"`
	PortHistogram       [256]int `json:"port_histogram"`
	IDHistogram         [256]int `json:"id_histogram"`
	QnameUppercaseCount int      `json:"qname_uppercase_count"` // queries where QNAME had at least one uppercase letter
	QnameLowercaseCount int      `json:"qname_lowercase_count"` // queries where QNAME had at least one lowercase letter
	RandomnessScore     float64  `json:"randomness_score"`      // 0–100 from uniformity
}

// Thresholds (porttest): GREAT >= 3980, GOOD >= 296, else POOR.
// ID (0-65535): GREAT >= ~18900, GOOD >= ~1400, else POOR.
const (
	PortStddevGreat = 3980
	PortStddevGood  = 296
	IDStddevGreat   = 18900
	IDStddevGood    = 1400
)

// EntropyStore holds entropy runs keyed by runId; bounded and time-limited.
type EntropyStore struct {
	mu        sync.RWMutex
	byRun     map[string]*EntropyRun
	maxRuns   int
	retention time.Duration
	runOrder  []string
}

// EntropyMinSamples and EntropyMaxSamples are the allowed sample counts (100–1000).
const (
	EntropyMinSamples = 100
	EntropyMaxSamples = 1000
)

// NewEntropyStore creates a store with at most maxRuns and retention duration.
func NewEntropyStore(maxRuns int, retention time.Duration, _ int) *EntropyStore {
	if maxRuns <= 0 {
		maxRuns = 100
	}
	if retention <= 0 {
		retention = 10 * time.Minute
	}
	return &EntropyStore{
		byRun:     make(map[string]*EntropyRun),
		maxRuns:   maxRuns,
		retention: retention,
		runOrder:  nil,
	}
}

// Record adds one sample for the run. runId is the logical run (e.g. prefix of "runId-0"). qname is the QNAME as received (for 0x20).
func (s *EntropyStore) Record(runId string, sourcePort int, transactionID uint16, qname string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	cutoff := now.Add(-s.retention)
	s.pruneLocked(cutoff)

	run, ok := s.byRun[runId]
	if !ok {
		run = &EntropyRun{CreatedAt: now}
		s.byRun[runId] = run
		s.runOrder = append(s.runOrder, runId)
		if len(s.byRun) > s.maxRuns && len(s.runOrder) > 0 {
			old := s.runOrder[0]
			s.runOrder = s.runOrder[1:]
			delete(s.byRun, old)
		}
	}
	run.Samples = append(run.Samples, EntropySample{
		SourcePort:    sourcePort,
		TransactionID: transactionID,
		Qname:         qname,
		At:            now,
	})
}

func (s *EntropyStore) pruneLocked(cutoff time.Time) {
	for _, id := range s.runOrder {
		run := s.byRun[id]
		if run == nil || run.CreatedAt.Before(cutoff) {
			delete(s.byRun, id)
		}
	}
	newOrder := make([]string, 0, len(s.byRun))
	for _, id := range s.runOrder {
		if s.byRun[id] != nil {
			newOrder = append(newOrder, id)
		}
	}
	s.runOrder = newOrder
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	var sq float64
	for _, v := range values {
		d := v - mean
		sq += d * d
	}
	return math.Sqrt(sq / float64(len(values)-1))
}

func rating(stddev float64, great, good float64) string {
	if stddev >= great {
		return "GREAT"
	}
	if stddev >= good {
		return "GOOD"
	}
	return "POOR"
}

const numHistogramBuckets = 256

func computeEntropyResult(samples []EntropySample) *EntropyResult {
	if len(samples) == 0 {
		return nil
	}
	ports := make([]float64, len(samples))
	ids := make([]float64, len(samples))
	var portHist [256]int
	var idHist [256]int
	for i, s := range samples {
		ports[i] = float64(s.SourcePort)
		ids[i] = float64(s.TransactionID)
		// Port 0–65535 → bucket 0–255; clamp for odd values
		p := s.SourcePort
		if p < 0 {
			p = 0
		}
		if p > 65535 {
			p = 65535
		}
		portHist[p*256/65536]++
		idHist[s.TransactionID>>8]++
	}
	portSd := stddev(ports)
	idSd := stddev(ids)

	upper, lower := qnameCaseCounts(samples)
	chi2Port, chi2ID := chi2Uniform256(portHist, idHist, len(samples))
	randScore := randomnessScoreFromChi2(chi2Port, chi2ID)

	return &EntropyResult{
		PortStddev:          math.Round(portSd*100) / 100,
		IDStddev:            math.Round(idSd*100) / 100,
		PortChi2:            math.Round(chi2Port*10) / 10,
		IDChi2:              math.Round(chi2ID*10) / 10,
		PortRating:          rating(portSd, PortStddevGreat, PortStddevGood),
		IDRating:            rating(idSd, IDStddevGreat, IDStddevGood),
		SamplesCount:        len(samples),
		PortHistogram:       portHist,
		IDHistogram:         idHist,
		QnameUppercaseCount: upper,
		QnameLowercaseCount: lower,
		RandomnessScore:     randScore,
	}
}

// qnameCaseCounts returns the number of samples whose QNAME contained at least one uppercase letter and at least one lowercase letter (0x20).
func qnameCaseCounts(samples []EntropySample) (uppercaseCount, lowercaseCount int) {
	for _, s := range samples {
		if s.Qname == "" {
			continue
		}
		if s.Qname != strings.ToLower(s.Qname) {
			uppercaseCount++
		}
		if s.Qname != strings.ToUpper(s.Qname) {
			lowercaseCount++
		}
	}
	return uppercaseCount, lowercaseCount
}

// chi2Uniform256 returns chi-squared statistic for uniformity over 256 buckets (df=255) for port and ID histograms.
func chi2Uniform256(portHist, idHist [256]int, n int) (chi2Port, chi2ID float64) {
	if n < 2 {
		return 0, 0
	}
	exp := float64(n) / float64(numHistogramBuckets)
	for i := 0; i < numHistogramBuckets; i++ {
		o := float64(portHist[i])
		d := o - exp
		chi2Port += d * d / exp
		o = float64(idHist[i])
		d = o - exp
		chi2ID += d * d / exp
	}
	return chi2Port, chi2ID
}

// randomnessScoreFromChi2 returns 0–100 from average chi-squared (higher = more uniform). df=255: critical ~293 at 0.05.
func randomnessScoreFromChi2(chi2Port, chi2ID float64) float64 {
	chi2 := (chi2Port + chi2ID) / 2
	score := 100 - math.Min(100, chi2/3)
	if score < 0 {
		score = 0
	}
	return math.Round(score*10) / 10
}

// Result returns the cached or freshly computed result for runId with at least minSamples (clamped to EntropyMinSamples–EntropyMaxSamples).
func (s *EntropyStore) Result(runId string, minSamples int) *EntropyResult {
	if minSamples < EntropyMinSamples {
		minSamples = EntropyMinSamples
	}
	if minSamples > EntropyMaxSamples {
		minSamples = EntropyMaxSamples
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.byRun[runId]
	if run == nil || len(run.Samples) < minSamples {
		return nil
	}
	if run.Result != nil && run.ResultN == minSamples {
		return run.Result
	}
	use := run.Samples[:minSamples]
	run.Result = computeEntropyResult(use)
	run.ResultN = minSamples
	return run.Result
}

// RunStatus returns samples count and result for polling. result is computed when samples >= minSamples.
func (s *EntropyStore) RunStatus(runId string, minSamples int) (samplesCount int, result *EntropyResult) {
	if minSamples < EntropyMinSamples {
		minSamples = EntropyMinSamples
	}
	if minSamples > EntropyMaxSamples {
		minSamples = EntropyMaxSamples
	}
	s.mu.RLock()
	run := s.byRun[runId]
	s.mu.RUnlock()
	if run == nil {
		return 0, nil
	}
	n := len(run.Samples)
	if n < minSamples {
		return n, nil
	}
	return n, s.Result(runId, minSamples)
}

// runIdSafe matches runId for API path (alphanumeric and hyphen only, length cap).
var runIdSafe = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,64}$`)

// ServeEntropyResult writes JSON result for GET /entropy/result/<runId>?n=100–1000 (default 250).
func (s *EntropyStore) ServeEntropyResult(w http.ResponseWriter, req *http.Request, runId string) {
	if !runIdSafe.MatchString(runId) {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	n := 250 // default
	if q := req.URL.Query().Get("n"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= EntropyMinSamples && v <= EntropyMaxSamples {
			n = v
		}
	}
	samplesCount, result := s.RunStatus(runId, n)
	type response struct {
		SamplesCount int            `json:"samples_count"`
		Result       *EntropyResult `json:"result,omitempty"`
	}
	resp := response{SamplesCount: samplesCount}
	if result != nil {
		resp.Result = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ParseEntropyRunId extracts the logical runId from a qname label like "runId-0" or "runId-25".
// We strip trailing -<digits> so "abc12-0" .. "abc12-25" all map to "abc12".
func ParseEntropyRunId(leftLabel string) string {
	leftLabel = strings.TrimSpace(leftLabel)
	// Find last "-" followed only by digits
	for i := len(leftLabel) - 1; i >= 0; i-- {
		if leftLabel[i] == '-' {
			suffix := leftLabel[i+1:]
			if suffix != "" && isDigits(suffix) {
				return leftLabel[:i]
			}
		}
	}
	return leftLabel
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// EntropyNSamples is the default number of requests for NewEntropyStore compatibility.
const EntropyNSamples = 250
