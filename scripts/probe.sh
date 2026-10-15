#!/usr/bin/env bash
# Raw-HTTP walkthrough of mid-interaction RAR remediation, no LLM involved.
# Uses the lab-only `mcp-probe` client (custom password grant) so it runs headless.
#   bash scripts/probe.sh            (from the host, with `docker compose up` running)
set -euo pipefail
AS=${AS:-http://localhost:8080}
MCP=${MCP:-http://localhost:3000/mcp}
PW_GRANT=urn:lab:params:oauth:grant-type:password

token() { # $1 = form field (scope=... or authorization_details=...)
  curl -sf -u mcp-probe:probe-secret -d grant_type=$PW_GRANT -d username=alice -d password=alice \
    --data-urlencode "$1" "$AS/token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
hdr() { echo; echo "=== $*"; }
post() { # $1 token, $2 body, [$3 session]
  curl -s -D - -o /tmp/probe_body -X POST "$MCP" \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2025-11-25' \
    ${3:+-H "mcp-session-id: $3"} -d "$2" | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate|mcp-session-id)'
  echo "body: $(head -c 400 /tmp/probe_body)"
}

hdr "1. no token -> 401 + resource_metadata"
curl -s -D - -o /dev/null -X POST "$MCP" -H 'content-type: application/json' -d '{}' | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate)'

echo; echo "AS advertises: $(curl -s $AS/.well-known/openid-configuration | python3 -c 'import json,sys;d=json.load(sys.stdin);print("authorization_details_types_supported=",d["authorization_details_types_supported"],"metadata endpoint=",d["authorization_details_types_metadata_endpoint"])')"

BASE=$(token "scope=mcp:basic")
hdr "2. initialize with the SESSION token (scope=mcp:basic)"
SID=$(post "$BASE" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | sed -nE 's/^mcp-session-id: (.*)$/\1/Ip')
echo "session: $SID"
post "$BASE" '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SID" >/dev/null

remediation_details() { # stdin: headers -> decoded authorization_details JSON
  sed -nE 's/^www-authenticate: .*authorization_remediation=([A-Za-z0-9_-]+).*/\1/Ip' |
    python3 -c 'import sys,json,base64; r=sys.stdin.read().strip(); r+="="*(-len(r)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(r))["authorization_details"]))'
}
iid() { python3 -c 'import sys,json; print(json.loads(sys.argv[1])[0]["instruction_id"])' "$1"; }
transfer() { # $1 id, $2 amount, [$3 idempotency_key]
  echo '{"jsonrpc":"2.0","id":'"$1"',"method":"tools/call","params":{"name":"transfer","arguments":{"from_account":"checking","pix_key":"carol@pix.example","amount":'"$2"${3:+',"idempotency_key":"'"$3"'"'}'}}}'
}

hdr "3. transfer with the session token -> 401 insufficient_authorization + authorization_remediation"
echo "   (this probe declares no elicitation capability, so the server skips the confirmation step)"
OUT=$(post "$BASE" "$(transfer 7 800)" "$SID"); echo "$OUT"
D7=$(echo "$OUT" | remediation_details)
echo "decoded authorization_details: $D7"
echo "-> instruction_id binds the grant to operation $(iid "$D7")"

OP7=$(token "authorization_details=$D7")
echo "one-shot token claims: $(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); d=json.loads(base64.urlsafe_b64decode(p)); print({k:d.get(k) for k in ["scope","authorization_details","exp"]})' "$OP7")"

hdr "4. the one-shot token is NOT a session token: get_accounts with it -> 403"
post "$OP7" '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_accounts","arguments":{}}}' "$SID"

hdr "5. a SECOND identical transfer (new request) -> its own operation, different instruction_id"
OUT=$(post "$BASE" "$(transfer 9 800)" "$SID"); D9=$(echo "$OUT" | remediation_details)
echo "request 7 -> $(iid "$D7")   request 9 -> $(iid "$D9")"

hdr "6. token approved for request 7's operation, presented on request 9 -> refused (bound to another operation)"
post "$OP7" "$(transfer 9 800)" "$SID"

hdr "7. the same token on request 7 (the operation it was approved for) -> 200, executed once"
post "$OP7" "$(transfer 7 800)" "$SID"

hdr "8. replay request 7 AGAIN with the spent token -> stored result, no second debit"
post "$OP7" "$(transfer 7 800)" "$SID"

hdr "9. idempotency_key: two NEW requests with the same key share ONE operation (same instruction_id)"
KEY="pay-$RANDOM-$RANDOM"
OUT=$(post "$BASE" "$(transfer 20 50 "$KEY")" "$SID"); D20=$(echo "$OUT" | remediation_details)
OUT=$(post "$BASE" "$(transfer 21 50 "$KEY")" "$SID"); D21=$(echo "$OUT" | remediation_details)
echo "request 20 -> $(iid "$D20")   request 21 -> $(iid "$D21")"
OPK=$(token "authorization_details=$D21")
post "$OPK" "$(transfer 21 50 "$KEY")" "$SID"
echo "-- a third request with the same key, plain session token -> stored result, no new authorization:"
post "$BASE" "$(transfer 22 50 "$KEY")" "$SID"
echo "-- same key, different amount -> refused:"
post "$BASE" "$(transfer 23 51 "$KEY")" "$SID"

hdr "10. naive batch with a NEW payee: registers it (commit), then needs authorization -> guard, partial result in-band"
NEWKEY="zed-$RANDOM@pix.example"
post "$BASE" '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"naive_batch_transfer","arguments":{"from_account":"checking","items":[{"pix_key":"'"$NEWKEY"'","amount":20}]}}}' "$SID"

hdr "11. balances with the session token (still valid, never replaced): exactly R$ 800 + R$ 50 debited"
post "$BASE" '{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"get_accounts","arguments":{}}}' "$SID"
