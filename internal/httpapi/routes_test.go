package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoutes_Index(t *testing.T) {
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "Gadget DNS") {
		t.Error("body should contain Gadget DNS")
	}
	// When DiagDomain is empty, zone falls back to example.com
	if !strings.Contains(rec.Body.String(), "example.com") {
		t.Error("body should contain zone (example.com when DiagDomain empty)")
	}
}

func TestRoutes_Healthcheck(t *testing.T) {
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type=%q", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Errorf("body=%q", rec.Body.String())
	}
}

func TestRoutes_Feed(t *testing.T) {
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	req := httptest.NewRequest(http.MethodGet, "/feed", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d want 200", rec.Code)
	}
}

func TestDiagStore_RecordAndAppendRelated(t *testing.T) {
	store := NewDiagStore(10, 15*time.Minute)
	token := "mytoken"
	clientAddr := "192.0.2.1:12345"

	// Record primary diag event (token.diag.<zone> query)
	primary := Event{
		Qname:      "mytoken.diag.example.com.",
		Qtype:      "TXT",
		ClientAddr: clientAddr,
		Transport:  "UDP",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	store.Record(token, primary)

	// Append a related event (e.g. apex DNSKEY from same client)
	related := Event{
		Qname:      "example.com.",
		Qtype:      "DNSKEY",
		ClientAddr: clientAddr,
		Transport:  "UDP",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	store.AppendRelated(token, clientAddr, related)

	records := store.Records(token)
	if len(records) != 1 {
		t.Fatalf("Records(%q): got %d records, want 1", token, len(records))
	}
	if records[0].Primary.Qname != primary.Qname {
		t.Errorf("Primary.Qname = %q, want %q", records[0].Primary.Qname, primary.Qname)
	}
	if len(records[0].Related) != 1 {
		t.Fatalf("Related: got %d events, want 1", len(records[0].Related))
	}
	if records[0].Related[0].Qname != related.Qname || records[0].Related[0].Qtype != related.Qtype {
		t.Errorf("Related[0] = %q %q, want %q %q",
			records[0].Related[0].Qname, records[0].Related[0].Qtype,
			related.Qname, related.Qtype)
	}
}

func TestRoutes_DiagShowsRelated(t *testing.T) {
	store := NewDiagStore(10, 15*time.Minute)
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	r.DiagStore = store
	r.DiagDomain = "example.com"

	token := "mytoken"
	clientAddr := "192.0.2.1:12345"
	store.Record(token, Event{
		Qname:      "mytoken.diag.example.com.",
		Qtype:      "TXT",
		ClientAddr: clientAddr,
		Transport:  "UDP",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})
	store.AppendRelated(token, clientAddr, Event{
		Qname:      "example.com.",
		Qtype:      "DNSKEY",
		ClientAddr: clientAddr,
		Transport:  "UDP",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})

	req := httptest.NewRequest(http.MethodGet, "/mytoken", nil)
	req.Host = "diag.example.com"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("code=%d want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mytoken.diag.example.com") {
		t.Error("body should contain primary qname mytoken.diag.example.com")
	}
	if !strings.Contains(body, "Related queries") {
		t.Error("body should contain 'Related queries' section")
	}
	if !strings.Contains(body, "example.com") || !strings.Contains(body, "DNSKEY") {
		t.Error("body should contain related qname example.com and type DNSKEY")
	}
}

func TestRoutes_Entropy(t *testing.T) {
	store := NewEntropyStore(10, 10*time.Minute, 26)
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	r.EntropyStore = store
	r.DiagDomain = "example.com"

	req := httptest.NewRequest(http.MethodGet, "/entropy", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /entropy: code=%d want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Entropy check") {
		t.Error("body should contain Entropy check")
	}
	if !strings.Contains(body, "example.com") {
		t.Error("body should contain zone example.com")
	}
}

func TestRoutes_EntropyResult(t *testing.T) {
	store := NewEntropyStore(10, 10*time.Minute, 26)
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	r.EntropyStore = store

	req := httptest.NewRequest(http.MethodGet, "/entropy/result/abc123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /entropy/result/abc123: code=%d want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type=%q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "samples_count") {
		t.Error("body should contain samples_count")
	}
}

func TestRoutes_EntropySubdomain204(t *testing.T) {
	r := NewRoutes(NewACMEResponder(), NewFeed(10))
	r.EntropyStore = NewEntropyStore(10, 10*time.Minute, 26)
	r.DiagDomain = "example.com"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "run0.entropy.example.com"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("Host *.entropy.<domain>: code=%d want 204", rec.Code)
	}
}
