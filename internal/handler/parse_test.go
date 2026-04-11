package handler

import (
	"reflect"
	"testing"
)

func TestIsSetOption(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"set-cookie-abc", true},
		{"set-cookie-", true},
		{"set-ede-5", true},
		{"set-ede-5-foo", true},
		{"set-flags-0x8180", true},
		{"set-rcode-3", true},
		{"set-status-NXDOMAIN", true},
		{"set-id-1234", true},
		{"set-nsid-foo", true},
		{"set-nsid-my-server", true},
		{"set-noedns", true},
		{"set-nocompress", true},
		{"setednspad-256", true},
		{"setednspad-128", true},
		{"set-ttl-20", true},
		{"set-ttl-0", true},
		{"set-delay-0", true},
		{"set-delay-100", true},
		{"set-delay-10-50", true},
		{"set-answer-1-2-3-4", true},
		{"set-answer-txt-hello", true},
		{"connection", false},
		{"myip", false},
		{"set-cookie", false},
		{"set-ttl", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSetOption(tt.label)
		if got != tt.want {
			t.Errorf("isSetOption(%q)=%v want %v", tt.label, got, tt.want)
		}
	}
}

func TestParseTopLevel(t *testing.T) {
	tests := []struct {
		qname  string
		domain string
		want   ParsedTopLevel
		ok     bool
	}{
		{"myip.example.com", "example.com", ParsedTopLevel{SetOptions: nil, Gadget: "myip"}, true},
		{"connection.example.com", "example.com", ParsedTopLevel{SetOptions: nil, Gadget: "connection"}, true},
		{"set-cookie-xyz.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-cookie-xyz"}, Gadget: ""}, true},
		{"set-cookie-abc.set-ttl-20.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-cookie-abc", "set-ttl-20"}, Gadget: ""}, true},
		{"set-cookie-abc.connection.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-cookie-abc"}, Gadget: "connection"}, true},
		{"a.b.example.com", "example.com", ParsedTopLevel{SetOptions: nil, Gadget: "b"}, true},
		{"example.com", "example.com", ParsedTopLevel{SetOptions: nil, Gadget: ""}, true},
		{"other.com", "example.com", ParsedTopLevel{}, false},
		{"notunder.example.org", "example.com", ParsedTopLevel{}, false},
		{"set-ede-5-foo.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-ede-5-foo"}, Gadget: ""}, true},
		{"set-flags-0x1234.myip.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-flags-0x1234"}, Gadget: "myip"}, true},
		{"set-rcode-5.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-rcode-5"}, Gadget: ""}, true},
		{"set-status-NXDOMAIN.myip.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-status-NXDOMAIN"}, Gadget: "myip"}, true},
		{"set-id-0xabcd.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-id-0xabcd"}, Gadget: ""}, true},
		{"set-nsid-my-server.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-nsid-my-server"}, Gadget: ""}, true},
		{"set-noedns.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-noedns"}, Gadget: ""}, true},
		{"set-answer-1-2-3-4.set-answer-5-6-7-8.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-answer-1-2-3-4", "set-answer-5-6-7-8"}, Gadget: ""}, true},
	}
	for _, tt := range tests {
		got, ok := parseTopLevel(tt.qname, tt.domain)
		if ok != tt.ok {
			t.Errorf("parseTopLevel(%q, %q) ok=%v want %v", tt.qname, tt.domain, ok, tt.ok)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseTopLevel(%q, %q)=%+v want %+v", tt.qname, tt.domain, got, tt.want)
		}
	}
}

func TestParseTopLevel_setAnswer(t *testing.T) {
	tests := []struct {
		qname  string
		domain string
		want   ParsedTopLevel
		ok     bool
	}{
		{"set-answer-1-2-3-4.set-answer-5-6-7-8.example.com", "example.com", ParsedTopLevel{SetOptions: []string{"set-answer-1-2-3-4", "set-answer-5-6-7-8"}, Gadget: ""}, true},
	}
	for _, tt := range tests {
		got, ok := parseTopLevel(tt.qname, tt.domain)
		if ok != tt.ok {
			t.Errorf("parseTopLevel(%q, %q) ok=%v want %v", tt.qname, tt.domain, ok, tt.ok)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseTopLevel(%q, %q)=%+v want %+v", tt.qname, tt.domain, got, tt.want)
		}
	}
}

func TestParseDiag_setAnswer(t *testing.T) {
	tests := []struct {
		qname  string
		domain string
		want   ParsedDiag
		ok     bool
	}{
		{"set-answer-1-2-3-4.set-answer-5-6-7-8.foo.diag.example.com", "example.com", ParsedDiag{SetOptions: []string{"set-answer-1-2-3-4", "set-answer-5-6-7-8"}, Gadget: "", Token: "foo"}, true},
	}
	for _, tt := range tests {
		got, ok := parseDiag(tt.qname, tt.domain)
		if ok != tt.ok {
			t.Errorf("parseDiag(%q, %q) ok=%v want %v", tt.qname, tt.domain, ok, tt.ok)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseDiag(%q, %q)=%+v want %+v", tt.qname, tt.domain, got, tt.want)
		}
	}
}

func TestIsValidSetOption_setDelay(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"set-delay-0", true},
		{"set-delay-100", true},
		{"set-delay-10-50", true},
		{"set-delay-300000", true},
		{"set-delay-300001", false},
		{"set-delay-50-50", true},
		{"set-delay-50-10", false},
		{"set-delay", false},
		{"set-delay-", false},
	}
	for _, tt := range tests {
		got := isValidSetOption(tt.label)
		if got != tt.want {
			t.Errorf("isValidSetOption(%q)=%v want %v", tt.label, got, tt.want)
		}
	}
}

func TestIsValidSetOption_setEdnsPad(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"setednspad-128", true},
		{"setednspad-256", true},
		{"setednspad-4096", true},
		{"setednspad-99", false},
		{"setednspad-4097", false},
		{"setednspad-127", false},
	}
	for _, tt := range tests {
		got := isValidSetOption(tt.label)
		if got != tt.want {
			t.Errorf("isValidSetOption(%q)=%v want %v", tt.label, got, tt.want)
		}
	}
}

func TestIsValidSetOption_setAnswer(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"set-answer-1-2-3-4", true},
		{"set-answer-0-0-0-0", true},
		{"set-answer-255-255-255-255", true},
		{"set-answer-txt-hello", true},
		{"set-answer-txt-", true},
		{"set-answer-1-2-3", false},
		{"set-answer-1-2-3-4-5", false},
		{"set-answer-256-0-0-1", false},
		{"set-nsid-foo", true},
		{"set-nsid-my-server", true},
		{"set-nsid", false},
		{"set-noedns", true},
	}
	for _, tt := range tests {
		got := isValidSetOption(tt.label)
		if got != tt.want {
			t.Errorf("isValidSetOption(%q)=%v want %v", tt.label, got, tt.want)
		}
	}
}

func TestParseDiag(t *testing.T) {
	tests := []struct {
		qname  string
		domain string
		want   ParsedDiag
		ok     bool
	}{
		{"foo.diag.example.com", "example.com", ParsedDiag{SetOptions: nil, Gadget: "", Token: "foo"}, true},
		{"mytoken.diag.example.com", "example.com", ParsedDiag{SetOptions: nil, Gadget: "", Token: "mytoken"}, true},
		{"connection.foo.diag.example.com", "example.com", ParsedDiag{SetOptions: nil, Gadget: "connection", Token: "foo"}, true},
		{"set-cookie-abcdef.set-ttl-20.token.diag.example.com", "example.com", ParsedDiag{SetOptions: []string{"set-cookie-abcdef", "set-ttl-20"}, Gadget: "", Token: "token"}, true},
		{"set-cookie-abc.connection.foo.diag.example.com", "example.com", ParsedDiag{SetOptions: []string{"set-cookie-abc"}, Gadget: "connection", Token: "foo"}, true},
		{"foo.diag.other.com", "example.com", ParsedDiag{}, false},
		{"connection.example.com", "example.com", ParsedDiag{}, false},
	}
	for _, tt := range tests {
		got, ok := parseDiag(tt.qname, tt.domain)
		if ok != tt.ok {
			t.Errorf("parseDiag(%q, %q) ok=%v want %v", tt.qname, tt.domain, ok, tt.ok)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseDiag(%q, %q)=%+v want %+v", tt.qname, tt.domain, got, tt.want)
		}
	}
}
