#!/usr/bin/env bash
# Integration tests for gadget-dns-server against a live server.
# Uses dig (UDP/TCP/DoT/DoH) and doggo (DoQ). Requires server to be already running.
# Config: GADGET_DNS_SERVER, GADGET_DNS_ZONE, GADGET_UDP_PORT, etc. (see --help).

set -eu

# --- Config (env with defaults) ---
SERVER="${GADGET_DNS_SERVER:-127.0.0.1}"
ZONE="${GADGET_DNS_ZONE:-example.com}"
UDP_PORT="${GADGET_UDP_PORT:-53}"
TCP_PORT="${GADGET_TCP_PORT:-53}"
DOT_PORT="${GADGET_DOT_PORT:-853}"
DOH_PORT="${GADGET_DOH_PORT:-443}"
DOQ_PORT="${GADGET_DOQ_PORT:-8853}"
DIG_TIMEOUT="${GADGET_DIG_TIMEOUT:-5}"

PASSED=0
FAILED=0

usage() {
  cat <<'EOF'
Usage: integration-tests.sh [--help]

Integration tests against a live gadget-dns-server. Server must already be running.
For DNSSEC tests (+dnssec returns RRSIG), start the server with --dnssec (and keys).

Environment (defaults):
  GADGET_DNS_SERVER   Server host (default: 127.0.0.1)
  GADGET_DNS_ZONE     Zone name (default: example.com)
  GADGET_UDP_PORT     UDP port (default: 53)
  GADGET_TCP_PORT     TCP port (default: 53)
  GADGET_DOT_PORT     DoT port (default: 853)
  GADGET_DOH_PORT     DoH port (default: 443)
  GADGET_DOQ_PORT     DoQ port (default: 8853); 0 = skip DoQ
  GADGET_DIG_TIMEOUT  Query timeout in seconds (default: 5)

DoQ tests require doggo (go install github.com/mr-karan/doggo/cmd/doggo@latest).
EOF
}

if [[ "${1:-}" = "--help" ]] || [[ "${1:-}" = "-h" ]]; then
  usage
  exit 0
fi

# --- Helpers: run dig/doggo ---
run_dig_short() {
  local transport="$1"
  local qname="$2"
  local qtype="${3:-A}"
  local opts="+short +time=${DIG_TIMEOUT}"
  case "$transport" in
    UDP) dig $opts -p "$UDP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    TCP) dig +tcp $opts -p "$TCP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoT) dig +tls $opts -p "$DOT_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoH) dig +https $opts -p "$DOH_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    *) echo "run_dig_short: unknown transport $transport" >&2; return 1 ;;
  esac
}

run_dig_status() {
  local transport="$1"
  local qname="$2"
  local qtype="${3:-A}"
  local opts="+noall +comments +answer +time=${DIG_TIMEOUT}"
  case "$transport" in
    UDP) dig $opts -p "$UDP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    TCP) dig +tcp $opts -p "$TCP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoT) dig +tls $opts -p "$DOT_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoH) dig +https $opts -p "$DOH_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    *) echo "run_dig_status: unknown transport $transport" >&2; return 1 ;;
  esac
}

# Like run_dig_status but with +dnssec (DO bit) so server returns RRSIGs when DNSSEC is enabled.
run_dig_status_dnssec() {
  local transport="$1"
  local qname="$2"
  local qtype="${3:-A}"
  local opts="+noall +comments +answer +dnssec +time=${DIG_TIMEOUT}"
  case "$transport" in
    UDP) dig $opts -p "$UDP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    TCP) dig +tcp $opts -p "$TCP_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoT) dig +tls $opts -p "$DOT_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    DoH) dig +https $opts -p "$DOH_PORT" "@${SERVER}" "$qname" "$qtype" ;;
    *) echo "run_dig_status_dnssec: unknown transport $transport" >&2; return 1 ;;
  esac
}

run_doggo_short() {
  local qname="$1"
  local qtype="${2:-A}"
  if ! command -v doggo &>/dev/null; then
    return 2
  fi
  if [[ "${DOQ_PORT:-0}" -eq 0 ]]; then
    return 2
  fi
  doggo "$qname" "$qtype" "@quic://${SERVER}:${DOQ_PORT}" --short 2>/dev/null || true
}

# Strip RRSIG (and other non-data) lines from dig +short output when DNSSEC is used.
# RRSIG lines look like "TXT 13 4 0 20260209171410 ..."; data lines are quoted or plain.
filter_short_answer() {
  local text="$1"
  echo "$text" | grep -v '^$' | grep -vE '^[A-Z]+ [0-9]+ [0-9]+ [0-9]+ ' || true
}

# --- Assertions (exit 1 + message on failure) ---
assert_noerror() {
  local output="$1"
  if ! echo "$output" | grep -q 'status: NOERROR'; then
    echo "FAIL: expected status NOERROR" >&2
    echo "$output" | head -20 >&2
    exit 1
  fi
}

assert_one_line() {
  local text="$1"
  local lines
  lines=$(echo "$text" | grep -v '^$' | wc -l)
  if [[ "$lines" -ne 1 ]]; then
    echo "FAIL: expected exactly one line, got $lines" >&2
    echo "$text" >&2
    exit 1
  fi
}

assert_numeric() {
  local line="$1"
  if ! echo "$line" | grep -qE '^[0-9]+$'; then
    echo "FAIL: expected numeric line, got: $line" >&2
    exit 1
  fi
}

# myaddr returns one TXT RR with two strings (address, port). dig +short may output
# two lines (one string per line) or one line with two quoted tokens; accept both.
assert_two_lines_second_numeric() {
  local text="$1"
  local line1 line2
  local line_count
  line_count=$(echo "$text" | grep -v '^$' | wc -l)
  if [[ "$line_count" -eq 2 ]]; then
    line1=$(echo "$text" | sed -n '1p')
    line2=$(echo "$text" | sed -n '2p')
  elif [[ "$line_count" -eq 1 ]]; then
    # One line: "addr" "port" or addr port — take first and second token
    line1=$(echo "$text" | awk '{ print $1 }' | tr -d '"')
    line2=$(echo "$text" | awk '{ print $2 }' | tr -d '"')
  else
    echo "FAIL: expected two lines (or one line with two tokens) for myaddr, got $line_count" >&2
    echo "$text" >&2
    exit 1
  fi
  if [[ -z "$line2" ]]; then
    echo "FAIL: expected two values for myaddr (address and port), got one or none" >&2
    echo "$text" >&2
    exit 1
  fi
  if ! echo "$line2" | grep -qE '^[0-9]+$'; then
    echo "FAIL: expected second value numeric (port), got: $line2" >&2
    exit 1
  fi
  if [[ -z "$line1" ]]; then
    echo "FAIL: expected first value non-empty (host)" >&2
    exit 1
  fi
}

assert_valid_ip() {
  local line="$1"
  if echo "$line" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    return 0
  fi
  if echo "$line" | grep -qE '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'; then
    return 0
  fi
  echo "FAIL: expected valid IPv4 or IPv6, got: $line" >&2
  exit 1
}

assert_connection_format() {
  local line="$1"
  if ! echo "$line" | grep -q '://'; then
    echo "FAIL: expected connection URL with ://, got: $line" >&2
    exit 1
  fi
}

assert_protocol() {
  local line="$1"
  case "$line" in
    UDP|TCP|DoT|DoH|DoQ) return 0 ;;
    *) echo "FAIL: expected protocol UDP|TCP|DoT|DoH|DoQ, got: $line" >&2; exit 1 ;;
  esac
}

# --- Test runner ---
test_pass() {
  echo "  OK $*"
  ((PASSED++)) || true
}

test_fail() {
  echo "  FAIL $*" >&2
  ((FAILED++)) || true
}

run_test() {
  local name="$1"
  shift
  if ( set -e; "$@" ); then
    test_pass "$name"
  else
    test_fail "$name"
  fi
}

# --- Tests (by transport) ---
test_apex_soa() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "$ZONE" SOA)
  assert_noerror "$out"
  if ! echo "$out" | grep -q "SOA"; then
    echo "FAIL: SOA not in answer" >&2
    exit 1
  fi
}

test_myip_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "myip.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "myip.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_valid_ip "$(echo "$txt" | tr -d '"')"
}

test_myport_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "myport.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "myport.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_numeric "$(echo "$txt" | tr -d '"')"
}

test_myaddr_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "myaddr.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "myaddr.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_two_lines_second_numeric "$(echo "$txt" | tr -d '"')"
}

test_connection_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "connection.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "connection.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_connection_format "$(echo "$txt" | tr -d '"')"
}

test_protocol_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "protocol.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "protocol.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_protocol "$(echo "$txt" | tr -d '"')"
}

test_counter_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "counter.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "counter.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_numeric "$(echo "$txt" | tr -d '"')"
}

test_random_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "random.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "random.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  if [[ -z "$(echo "$txt" | tr -d '[:space:]')" ]]; then
    echo "FAIL: random TXT empty" >&2
    exit 1
  fi
}

test_ttl0_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "ttl-0.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "ttl-0.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_numeric "$(echo "$txt" | tr -d '"')"
}

test_timestamp0_txt() {
  local transport="$1"
  local out
  out=$(run_dig_status "$transport" "timestamp-0.${ZONE}" TXT)
  assert_noerror "$out"
  local txt
  txt=$(run_dig_short "$transport" "timestamp-0.${ZONE}" TXT)
  txt=$(filter_short_answer "$txt")
  assert_one_line "$txt"
  assert_numeric "$(echo "$txt" | tr -d '"')"
}

# DNSSEC: when using +dnssec (DO bit), server must return RRSIGs. Passes only when server is run with --dnssec.
test_dnssec_returns_rrsig() {
  local transport="$1"
  local out
  out=$(run_dig_status_dnssec "$transport" "$ZONE" SOA)
  assert_noerror "$out"
  if ! echo "$out" | grep -q "RRSIG"; then
    echo "FAIL: +dnssec query did not return RRSIG (start server with --dnssec for this test)" >&2
    echo "$out" | head -15 >&2
    exit 1
  fi
}

# --- DoQ tests (doggo) ---
skip_doq() {
  ! command -v doggo &>/dev/null || [[ "${DOQ_PORT:-0}" -eq 0 ]]
}

test_doq_apex_soa() {
  if skip_doq; then
    return 0
  fi
  local out
  out=$(run_doggo_short "$ZONE" SOA)
  if [[ -z "$out" ]]; then
    echo "FAIL: DoQ SOA empty" >&2
    exit 1
  fi
  # doggo --short for SOA prints record values (owner mname rname serial refresh retry expire minttl), not "SOA"
  if ! echo "$out" | grep -qF "$ZONE"; then
    echo "FAIL: DoQ SOA answer missing zone name (expected $ZONE)" >&2
    echo "$out" >&2
    exit 1
  fi
}

test_doq_myaddr_txt() {
  if skip_doq; then
    return 0
  fi
  local out
  out=$(run_doggo_short "myaddr.${ZONE}" TXT)
  # doggo --short may include ;; lines; strip to data only; strip RRSIG lines (DNSSEC)
  local data
  data=$(echo "$out" | grep -v '^;;')
  data=$(filter_short_answer "$data")
  data=$(echo "$data" | sed 's/^"//;s/"$//' | tr -d '"')
  assert_two_lines_second_numeric "$data"
}

test_doq_protocol_txt() {
  if skip_doq; then
    return 0
  fi
  local out
  out=$(run_doggo_short "protocol.${ZONE}" TXT)
  local line
  line=$(echo "$out" | grep -v '^;;' | head -1 | tr -d '"')
  assert_protocol "$line"
  if [[ "$line" != "DoQ" ]]; then
    echo "FAIL: expected protocol DoQ over DoQ transport, got: $line" >&2
    exit 1
  fi
}

# --- Main ---
main() {
  echo "Integration tests: SERVER=$SERVER ZONE=$ZONE (UDP=$UDP_PORT TCP=$TCP_PORT DoT=$DOT_PORT DoH=$DOH_PORT DoQ=$DOQ_PORT)"
  echo

  for transport in UDP TCP; do
    echo "--- $transport ---"
    run_test "apex SOA" test_apex_soa "$transport"
    run_test "myip TXT" test_myip_txt "$transport"
    run_test "myport TXT" test_myport_txt "$transport"
    run_test "myaddr TXT" test_myaddr_txt "$transport"
    run_test "connection TXT" test_connection_txt "$transport"
    run_test "protocol TXT" test_protocol_txt "$transport"
    run_test "counter TXT" test_counter_txt "$transport"
    run_test "random TXT" test_random_txt "$transport"
    run_test "ttl-0 TXT" test_ttl0_txt "$transport"
    run_test "timestamp-0 TXT" test_timestamp0_txt "$transport"
    # +dnssec returns RRSIG only when server is run with --dnssec; run once (UDP)
    if [[ "$transport" = "UDP" ]]; then
      run_test "+dnssec returns RRSIG" test_dnssec_returns_rrsig "$transport"
    fi
  done

  for transport in DoT DoH; do
    echo "--- $transport ---"
    run_test "apex SOA" test_apex_soa "$transport"
    run_test "myaddr TXT" test_myaddr_txt "$transport"
    run_test "protocol TXT" test_protocol_txt "$transport"
    run_test "counter TXT" test_counter_txt "$transport"
  done

  echo "--- DoQ (doggo) ---"
  if command -v doggo &>/dev/null && [[ "${DOQ_PORT:-0}" -ne 0 ]]; then
    run_test "apex SOA" test_doq_apex_soa
    run_test "myaddr TXT" test_doq_myaddr_txt
    run_test "protocol TXT (DoQ)" test_doq_protocol_txt
  else
    echo "  SKIP DoQ (install doggo and set GADGET_DOQ_PORT to enable)"
  fi

  echo
  echo "Summary: $PASSED passed, $FAILED failed"
  if [[ "$FAILED" -gt 0 ]]; then
    exit 1
  fi
}

main
