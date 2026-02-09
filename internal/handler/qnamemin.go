package handler

import (
	"sync"
	"time"
)

// QnameMinRecorder records *.qname-min.<zone> queries per client IP and returns the recent sequence for QNAME minimization testing (RFC 7816).
type QnameMinRecorder interface {
	Record(clientIP, qname string)
	GetRecentSequence(clientIP string) []string
}

type qnameMinEntry struct {
	qname string
	at    time.Time
}

// QnameMinStore holds recent qname-min queries per client IP for reporting minimization sequence.
type QnameMinStore struct {
	mu           sync.RWMutex
	byClient     map[string][]qnameMinEntry
	retention    time.Duration
	maxPerClient int
}

// NewQnameMinStore creates a store with the given retention (e.g. 60*time.Second) and max entries per client (e.g. 50).
func NewQnameMinStore(retention time.Duration, maxPerClient int) *QnameMinStore {
	if retention <= 0 {
		retention = 60 * time.Second
	}
	if maxPerClient <= 0 {
		maxPerClient = 50
	}
	return &QnameMinStore{
		byClient:     make(map[string][]qnameMinEntry),
		retention:    retention,
		maxPerClient: maxPerClient,
	}
}

// Record appends a qname for the client IP and prunes old entries.
func (s *QnameMinStore) Record(clientIP, qname string) {
	if clientIP == "" || qname == "" {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byClient[clientIP]
	cutoff := now.Add(-s.retention)
	// Prune old
	for len(list) > 0 && list[0].at.Before(cutoff) {
		list = list[1:]
	}
	list = append(list, qnameMinEntry{qname: qname, at: now})
	if len(list) > s.maxPerClient {
		list = list[len(list)-s.maxPerClient:]
	}
	s.byClient[clientIP] = list
}

// GetRecentSequence returns qnames for the client in time order (oldest first), then prunes old entries.
func (s *QnameMinStore) GetRecentSequence(clientIP string) []string {
	if clientIP == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byClient[clientIP]
	now := time.Now().UTC()
	cutoff := now.Add(-s.retention)
	for len(list) > 0 && list[0].at.Before(cutoff) {
		list = list[1:]
	}
	s.byClient[clientIP] = list
	if len(list) == 0 {
		delete(s.byClient, clientIP)
		return nil
	}
	out := make([]string, len(list))
	for i := range list {
		out[i] = list[i].qname
	}
	return out
}
