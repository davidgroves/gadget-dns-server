package handler

import (
	"testing"
	"time"
)

func TestQnameMinStore_RecordAndGetRecentSequence(t *testing.T) {
	store := NewQnameMinStore(60*time.Second, 50)
	clientIP := "192.168.1.1"

	store.Record(clientIP, "qname-min.example.com.")
	store.Record(clientIP, "d.qname-min.example.com.")
	store.Record(clientIP, "c.d.qname-min.example.com.")

	seq := store.GetRecentSequence(clientIP)
	if len(seq) != 3 {
		t.Fatalf("GetRecentSequence: got %d entries, want 3", len(seq))
	}
	if seq[0] != "qname-min.example.com." {
		t.Errorf("seq[0]=%q want qname-min.example.com.", seq[0])
	}
	if seq[1] != "d.qname-min.example.com." {
		t.Errorf("seq[1]=%q want d.qname-min.example.com.", seq[1])
	}
	if seq[2] != "c.d.qname-min.example.com." {
		t.Errorf("seq[2]=%q want c.d.qname-min.example.com.", seq[2])
	}
}

func TestQnameMinStore_EmptyClient(t *testing.T) {
	store := NewQnameMinStore(60*time.Second, 50)
	seq := store.GetRecentSequence("10.0.0.1")
	if seq != nil {
		t.Errorf("GetRecentSequence(unknown client): got %v want nil", seq)
	}
}

func TestQnameMinStore_Pruning(t *testing.T) {
	store := NewQnameMinStore(10*time.Millisecond, 50)
	clientIP := "127.0.0.1"

	store.Record(clientIP, "first.example.com.")
	time.Sleep(15 * time.Millisecond)
	store.Record(clientIP, "second.example.com.")

	seq := store.GetRecentSequence(clientIP)
	if len(seq) != 1 {
		t.Errorf("after retention: got %d entries want 1 (first pruned)", len(seq))
	}
	if len(seq) > 0 && seq[0] != "second.example.com." {
		t.Errorf("seq[0]=%q want second.example.com.", seq[0])
	}
}
