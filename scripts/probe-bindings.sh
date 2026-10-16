#!/usr/bin/env bash
# Raw-HTTP walkthrough of binding NEGOTIATION and of the MRTR binding, no LLM involved.
#  - The client discloses, per request, which in-band forms of "authorization required" it handles:
#      capabilities.extensions["lab.stepup/rar-remediation"] = {bindings: [preference order]}
#    and the server answers with the first one it offers, or with the interoperable 401.
#  - MRTR binding: the authorization step is a successful `input_required` result (MCP 2026-07-28
#    Multi Round-Trip Requests), not a 401/error.
#   docker compose up -d                 (default CHALLENGE_BINDING=negotiate)
#   bash scripts/probe-bindings.sh
set -euo pipefail
AS=${AS:-http://localhost:8080}
MCP=${MCP:-http://localhost:3000/mcp}
PW_GRANT=urn:lab:params:oauth:grant-type:password
EXT=lab.stepup/rar-remediation

token() { # $1 = form field (scope=... or authorization_details=...)
  curl -sf -u mcp-probe:probe-secret -d grant_type=$PW_GRANT -d username=alice -d password=alice \
    --data-urlencode "$1" "$AS/token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
hdr() { echo; echo "=== $*"; }
# transfer ID AMOUNT CAPS_JSON [REQUEST_STATE] -> tools/call transfer with the 2026-07-28 _meta envelope
transfer() {
  python3 - "$@" <<'PY'
import json, sys
id_, amount, caps = sys.argv[1], float(sys.argv[2]), json.loads(sys.argv[3])
params = {"name": "transfer", "arguments": {"from_account": "checking", "pix_key": "dave@pix.example", "amount": amount},
          "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "probe-bindings", "version": "0"},
                    "io.modelcontextprotocol/clientCapabilities": caps}}
if len(sys.argv) > 4: params["requestState"] = sys.argv[4]   # MRTR retry: echo it byte-exact
print(json.dumps({"jsonrpc": "2.0", "id": int(id_), "method": "tools/call", "params": params}))
PY
}
post() { # $1 token, $2 tools/call transfer body -> prints status line; body in /tmp/probe_body
  curl -s -D - -o /tmp/probe_body -X POST "$MCP" \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2026-07-28' \
    -H 'mcp-method: tools/call' -H 'mcp-name: transfer' -d "$2" \
    | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate)' | cut -c1-160
}
show() { # summarize the JSON-RPC body
  python3 - <<'PY'
import json
b = json.load(open("/tmp/probe_body"))
if "error" in b: print(f"  error {b['error']['code']}: {b['error']['message']}"); raise SystemExit
r = b["result"]
print(f"  resultType={r.get('resultType')} isError={r.get('isError', False)}")
if r.get("requestState"): print(f"  requestState={r['requestState'][:48]}…")
if r.get("inputRequests"): print(f"  inputRequests={list(r['inputRequests'])}")
hint = (r.get("_meta") or {}).get("lab.stepup/authorization_required")
if hint:
    print(f"  _meta[lab.stepup/authorization_required]: error={hint['error']} operation_id={hint['operation_id']}")
    print(f"    authorization_details={json.dumps(hint['authorization_remediation']['authorization_details'])}")
for c in r.get("content", []): print(f"  content: {c.get('text', '')[:150]}")
PY
}
field() { python3 -c 'import json,sys; r=json.load(open("/tmp/probe_body"))["result"]; print(eval(sys.argv[1]))' "$1"; }

BASE=$(token "scope=mcp:basic")
caps() { echo '{"extensions":{"'$EXT'":'"$1"'}}'; }   # $1 = the extension's settings object
WITH_EXT=$(caps '{"bindings":["mrtr"]}')

hdr "1. server/discover: the server advertises the in-band forms it offers"
curl -s -X POST "$MCP" -H "authorization: Bearer $BASE" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2026-07-28' -H 'mcp-method: server/discover' \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"probe-bindings","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}' \
  | python3 -c 'import json,sys; print("  capabilities.extensions =", json.load(sys.stdin)["result"]["capabilities"].get("extensions"))'

hdr "2. negotiation: the same transfer, four clients"
echo "-- 2a. declares nothing -> the interoperable default, 401 insufficient_authorization"
post "$BASE" "$(transfer 21 300 '{}')"
echo "-- 2b. declares {bindings: [inband]} -> 200 with JSON-RPC error -32010"
post "$BASE" "$(transfer 22 300 "$(caps '{"bindings":["inband"]}')")"; show
echo "-- 2c. declares {bindings: [mrtr, inband]} -> its first choice: 200 resultType=input_required"
post "$BASE" "$(transfer 23 300 "$(caps '{"bindings":["mrtr","inband"]}')")"; show
echo "-- 2d. declares {bindings: [carrier-pigeon]} -> nothing in common: 401"
post "$BASE" "$(transfer 24 300 "$(caps '{"bindings":["carrier-pigeon"]}')")"
echo "   (declaring the extension without bindings means [mrtr])"

hdr "3. MRTR end to end: declares {bindings: [mrtr]} -> 200, resultType=input_required (NOT an error)"
post "$BASE" "$(transfer 3 300 "$WITH_EXT")"; show
STATE=$(field 'r["requestState"]')
DETAILS=$(field 'json.dumps(r["_meta"]["lab.stepup/authorization_required"]["authorization_remediation"]["authorization_details"])')

hdr "4. a naive retry (requestState echoed, still the session token) -> the same step again, nothing executed"
post "$BASE" "$(transfer 4 300 "$WITH_EXT" "$STATE")"; show

hdr "5. one-shot token for exactly the hinted authorization_details; retry with requestState + token -> executed once"
OP=$(token "authorization_details=$DETAILS")
post "$OP" "$(transfer 5 300 "$WITH_EXT" "$STATE")"; show

hdr "6. the same retry again -> stored result, no second debit"
post "$OP" "$(transfer 6 300 "$WITH_EXT" "$STATE")"; show

hdr "7. requestState is sealed: a tampered value is rejected before the tool runs"
post "$BASE" "$(transfer 7 300 "$WITH_EXT" "${STATE%?}x")"; show

hdr "8. requestState for this operation on a call with other arguments (R\$ 999) -> refused"
post "$BASE" "$(transfer 8 999 "$WITH_EXT" "$STATE")"; show
