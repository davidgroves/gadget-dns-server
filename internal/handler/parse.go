package handler

import (
	"strconv"
	"strings"
)

// ParsedTopLevel is the result of parsing a qname under the zone (top-level, not under .diag).
type ParsedTopLevel struct {
	SetOptions []string // leading set-* labels (set-cookie-*, set-ede-*, set-flags-*, set-rcode-*, set-status-*, set-id-*, set-ttl-*, set-answer-*, set-answer-plaintext-*)
	Gadget     string   // last remaining label, or empty if only set-options
}

// ParsedDiag is the result of parsing a qname under .token.diag.<zone>.
type ParsedDiag struct {
	SetOptions []string // leading set-* labels in the part before token (includes set-answer-*, set-answer-plaintext-*)
	Gadget     string   // optional gadget label
	Token      string   // the label immediately before .diag.<zone>
}

// isSetOption returns true if label is a set-option (set-cookie-*, set-ede-*, set-flags-*, set-rcode-*, set-status-*, set-id-*, set-ttl-*, set-answer-*, set-answer-plaintext-*).
func isSetOption(label string) bool {
	return strings.HasPrefix(label, prefixSetCookie) ||
		strings.HasPrefix(label, prefixSetEDE) ||
		strings.HasPrefix(label, prefixSetFlags) ||
		strings.HasPrefix(label, prefixSetRcode) ||
		strings.HasPrefix(label, prefixSetStatus) ||
		strings.HasPrefix(label, prefixSetID) ||
		strings.HasPrefix(label, prefixSetTTL) ||
		strings.HasPrefix(label, prefixSetAnswer)
}

// isValidSetOption returns true if the set-option label is valid (parseable). Used to return NXDOMAIN for invalid set-option-only names.
func isValidSetOption(label string) bool {
	if strings.HasPrefix(label, prefixSetCookie) {
		return isValidCookieHex(label[len(prefixSetCookie):])
	}
	if strings.HasPrefix(label, prefixSetEDE) {
		_, _, ok := parseSetEDELabel(label)
		return ok
	}
	if strings.HasPrefix(label, prefixSetFlags) {
		_, ok := parseFlagsBitmask(label[len(prefixSetFlags):])
		return ok
	}
	if strings.HasPrefix(label, prefixSetRcode) {
		_, ok := parseRcodeValue(label[len(prefixSetRcode):])
		return ok
	}
	if strings.HasPrefix(label, prefixSetStatus) {
		_, ok := parseRcodeValue(label[len(prefixSetStatus):])
		return ok
	}
	if strings.HasPrefix(label, prefixSetID) {
		_, ok := parseSetIDValue(label[len(prefixSetID):])
		return ok
	}
	if strings.HasPrefix(label, prefixSetTTL) {
		nStr := label[len(prefixSetTTL):]
		n, err := strconv.ParseUint(nStr, 10, 32)
		return err == nil && n <= maxTTL
	}
	if strings.HasPrefix(label, prefixSetAnswerPlaintext) {
		return true // any suffix is valid plaintext
	}
	if strings.HasPrefix(label, prefixSetAnswer) {
		return isValidSetAnswerALabel(label)
	}
	return false
}

// isValidSetAnswerALabel returns true if label is set-answer-<a>-<b>-<c>-<d> with each octet 0-255.
func isValidSetAnswerALabel(label string) bool {
	if !strings.HasPrefix(label, prefixSetAnswer) || strings.HasPrefix(label, prefixSetAnswerPlaintext) {
		return false
	}
	rest := label[len(prefixSetAnswer):]
	parts := strings.Split(rest, "-")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return false
		}
		_ = n
	}
	return true
}

// parseTopLevel parses qname under domain into set-options and gadget.
// qname and domain should be lowercased with no trailing dot.
// Returns (ParsedTopLevel, true) if qname is under domain, (ParsedTopLevel{}, false) otherwise.
func parseTopLevel(qname, domain string) (ParsedTopLevel, bool) {
	if qname == domain {
		return ParsedTopLevel{}, true
	}
	suffix := "." + domain
	if !strings.HasSuffix(qname, suffix) {
		return ParsedTopLevel{}, false
	}
	prefix := strings.TrimSuffix(qname, suffix)
	if prefix == "" {
		return ParsedTopLevel{}, true
	}
	labels := strings.Split(prefix, ".")
	var setOptions []string
	var remainder []string
	for _, l := range labels {
		if isSetOption(l) {
			setOptions = append(setOptions, l)
		} else {
			remainder = append(remainder, l)
		}
	}
	var gadget string
	if len(remainder) > 0 {
		gadget = remainder[len(remainder)-1]
	}
	return ParsedTopLevel{SetOptions: setOptions, Gadget: gadget}, true
}

// parseDiag parses qname under .diag.<zone> into set-options, gadget, and token.
// qname and domain should be lowercased with no trailing dot.
// Returns (ParsedDiag, true) if qname has suffix .diag.<domain>, (ParsedDiag{}, false) otherwise.
func parseDiag(qname, domain string) (ParsedDiag, bool) {
	diagBase := ".diag." + domain
	if !strings.HasSuffix(qname, diagBase) {
		return ParsedDiag{}, false
	}
	prefix := strings.TrimSuffix(qname, diagBase)
	if prefix == "" {
		return ParsedDiag{Token: ""}, true
	}
	labels := strings.Split(prefix, ".")
	token := labels[len(labels)-1]
	remainder := labels[:len(labels)-1]
	var setOptions []string
	var rest []string
	for _, l := range remainder {
		if isSetOption(l) {
			setOptions = append(setOptions, l)
		} else {
			rest = append(rest, l)
		}
	}
	var gadget string
	if len(rest) > 0 {
		gadget = rest[len(rest)-1]
	}
	return ParsedDiag{SetOptions: setOptions, Gadget: gadget, Token: token}, true
}
