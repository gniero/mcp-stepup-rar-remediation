#!/usr/bin/env bash
# Raw-HTTP walkthrough of mid-interaction RAR remediation, no LLM involved.
# Uses the lab-only `mcp-probe` client (custom password grant) so it runs headless.
# Speaks MCP 2026-07-28: no initialize / no session; every request carries the protocol version,
# client info and capabilities in params._meta, mirrored in MCP-Protocol-Version / Mcp-Method /
# Mcp-Name headers.
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
V=2026-07-28
# rpc ID METHOD PARAMS_JSON [EXTRA_META_JSON] -> JSON-RPC request with the 2026-07-28 _meta envelope
rpc() {
  python3 - "$@" <<'PY'
import json, sys
id_, method, params = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
extra = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                   "io.modelcontextprotocol/clientInfo": {"name": "probe", "version": "0"},
                   "io.modelcontextprotocol/clientCapabilities": {}, **extra}
print(json.dumps({"jsonrpc": "2.0", "id": int(id_), "method": method, "params": params}))
PY
}
post() { # $1 token, $2 body
  local method name
  method=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["method"])' "$2")
  name=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("params",{}).get("name",""))' "$2")
  curl -s -D - -o /tmp/probe_body -X POST "$MCP" \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H "mcp-protocol-version: $V" \
    -H "mcp-method: $method" ${name:+-H "mcp-name: $name"} -d "$2" | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate)'
  echo "body: $(head -c 400 /tmp/probe_body)"
}

hdr "1. no token -> 401 + resource_metadata"
curl -s -D - -o /dev/null -X POST "$MCP" -H 'content-type: application/json' -d '{}' | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate)'

echo; echo "AS advertises: $(curl -s $AS/.well-known/openid-configuration | python3 -c 'import json,sys;d=json.load(sys.stdin);print("authorization_details_types_supported=",d["authorization_details_types_supported"],"metadata endpoint=",d["authorization_details_types_metadata_endpoint"])')"

BASE=$(token "scope=mcp:basic")
hdr "2. server/discover with the SESSION token (scope=mcp:basic). No initialize, no Mcp-Session-Id in 2026-07-28"
post "$BASE" "$(rpc 1 server/discover '{}')"

remediation_details() { # stdin: headers -> decoded authorization_details JSON
  sed -nE 's/^www-authenticate: .*authorization_remediation=([A-Za-z0-9_-]+).*/\1/Ip' |
    python3 -c 'import sys,json,base64; r=sys.stdin.read().strip(); r+="="*(-len(r)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(r))["authorization_details"]))'
}
iid() { python3 -c 'import sys,json; print(json.loads(sys.argv[1])[0]["instruction_id"])' "$1"; }
transfer() { # $1 id, $2 amount, [$3 idempotency_key], [$4 extra _meta json]
  rpc "$1" tools/call '{"name":"transfer","arguments":{"from_account":"checking","pix_key":"carol@pix.example","amount":'"$2"${3:+',"idempotency_key":"'"$3"'"'}'}}' "${4:-{\}}"
}

hdr "3. transfer with the session token -> 401 insufficient_authorization + authorization_remediation"
echo "   (this probe declares no elicitation capability, so the server skips the confirmation round)"
OUT=$(post "$BASE" "$(transfer 7 800)"); echo "$OUT"
D7=$(echo "$OUT" | remediation_details)
echo "decoded authorization_details: $D7"
echo "-> instruction_id binds the grant to operation $(iid "$D7")"

OP7=$(token "authorization_details=$D7")
echo "one-shot token claims: $(python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); d=json.loads(base64.urlsafe_b64decode(p)); print({k:d.get(k) for k in ["scope","authorization_details","exp"]})' "$OP7")"

hdr "4. the one-shot token is NOT a session token: get_accounts with it -> 403"
post "$OP7" "$(rpc 8 tools/call '{"name":"get_accounts","arguments":{}}')"

hdr "5. a SECOND identical transfer (new request) -> its own operation, different instruction_id"
OUT=$(post "$BASE" "$(transfer 9 800)"); D9=$(echo "$OUT" | remediation_details)
echo "request 7 -> $(iid "$D7")   request 9 -> $(iid "$D9")"

hdr "6a. token approved for request 7's operation, on a request that names request 9's operation -> refused"
post "$OP7" "$(transfer 10 800 "" '{"lab.stepup/operation_id":"'"$(iid "$D9")"'"}')"
hdr "6b. the same token on a transfer with different parameters (R\$ 900) -> refused"
post "$OP7" "$(transfer 11 900)"

hdr "7. replay request 7 with the token (the operation it was approved for) -> 200, executed once"
post "$OP7" "$(transfer 7 800)"

hdr "8. replay request 7 AGAIN with the spent token -> stored result, no second debit"
post "$OP7" "$(transfer 7 800)"

hdr "9. idempotency_key: two NEW requests with the same key share ONE operation (same instruction_id)"
KEY="pay-$RANDOM-$RANDOM"
OUT=$(post "$BASE" "$(transfer 20 50 "$KEY")"); D20=$(echo "$OUT" | remediation_details)
OUT=$(post "$BASE" "$(transfer 21 50 "$KEY")"); D21=$(echo "$OUT" | remediation_details)
echo "request 20 -> $(iid "$D20")   request 21 -> $(iid "$D21")"
OPK=$(token "authorization_details=$D21")
post "$OPK" "$(transfer 21 50 "$KEY")"
echo "-- a third request with the same key, plain session token -> stored result, no new authorization:"
post "$BASE" "$(transfer 22 50 "$KEY")"
echo "-- same key, different amount -> refused:"
post "$BASE" "$(transfer 23 51 "$KEY")"

hdr "10. naive batch with a NEW payee: registers it (commit), then needs authorization -> guard, partial result in-band"
NEWKEY="zed-$RANDOM@pix.example"
post "$BASE" "$(rpc 30 tools/call '{"name":"naive_batch_transfer","arguments":{"from_account":"checking","items":[{"pix_key":"'"$NEWKEY"'","amount":20}]}}')"

hdr "11. balances with the session token (still valid, never replaced): exactly R$ 800 + R$ 50 debited"
post "$BASE" "$(rpc 31 tools/call '{"name":"get_accounts","arguments":{}}')"
