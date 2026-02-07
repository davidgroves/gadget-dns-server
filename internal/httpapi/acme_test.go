package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestACMEResponder_SetAndServe(t *testing.T) {
	r := NewACMEResponder()
	r.Set("token123", "key-authz-value")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d want 200", rec.Code)
	}
	if rec.Body.String() != "key-authz-value" {
		t.Errorf("body=%q", rec.Body.String())
	}
}

func TestACMEResponder_NotFound(t *testing.T) {
	r := NewACMEResponder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/unknown", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code=%d want 404", rec.Code)
	}
}
