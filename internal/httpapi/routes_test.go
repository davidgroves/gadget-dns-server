package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if !strings.Contains(rec.Body.String(), "gadget-dns-server") {
		t.Error("body should contain gadget-dns-server")
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
