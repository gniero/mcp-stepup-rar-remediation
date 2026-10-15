#!/usr/bin/env bash
# Raw-HTTP walkthrough of the mid-interaction step-up, no LLM involved.
# Uses the lab-only `mcp-probe` client (password grant) so it runs headless.
#   ./scripts/probe.sh            (from the host, with `docker compose up` running)
set -euo pipefail
KC=${KC:-http://localhost:8080}
MCP=${MCP:-http://localhost:3000/mcp}
TOKEN_EP="$KC/realms/mcp/protocol/openid-connect/token"

token() { # $1 = scope
  curl -sf -d grant_type=password -d client_id=mcp-probe -d username=alice -d password=alice \
    --data-urlencode "scope=$1" "$TOKEN_EP" | sed -E 's/.*"access_token":"([^"]+)".*/\1/'
}
hdr() { echo; echo "=== $*"; }
post() { # $1 token, $2 body, [$3 session]
  curl -s -D - -o /tmp/probe_body -X POST "$MCP" \
    -H "authorization: Bearer $1" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2025-11-25' \
    ${3:+-H "mcp-session-id: $3"} -d "$2" | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate|mcp-session-id)'
  echo "body: $(cat /tmp/probe_body)"
}

hdr "1. no token -> 401 + resource_metadata"
curl -s -D - -o /dev/null -X POST "$MCP" -H 'content-type: application/json' -d '{}' | tr -d '\r' | grep -iE '^(HTTP/|www-authenticate)'

BASE=$(token "mcp:basic")
hdr "2. initialize with baseline token"
SID=$(post "$BASE" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  | sed -nE 's/^mcp-session-id: (.*)$/\1/Ip')
echo "session: $SID"
post "$BASE" '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SID" >/dev/null

CALL='{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"transfer","arguments":{"from_account":"checking","pix_key":"carol@pix.example","amount":800}}}'
hdr "3. low-risk call works with baseline token"
post "$BASE" '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"transfer","arguments":{"from_account":"checking","pix_key":"bob@pix.example","amount":50}}}' "$SID"

hdr "4. high-risk call -> tool checkpoints an operation and challenges for THAT operation"
echo "   (this probe declares no elicitation capability, so the server skips the confirmation step)"
OUT=$(post "$BASE" "$CALL" "$SID"); echo "$OUT"
SCOPE=$(echo "$OUT" | sed -nE 's/^www-authenticate: .*scope="([^"]+)".*/\1/Ip')
echo "challenge scope: $SCOPE"

OPTOK=$(token "$SCOPE")
hdr "5. replay the SAME request (same id, same session) with the operation-bound token"
post "$OPTOK" "$CALL" "$SID"

hdr "6. replay it AGAIN (lost response / retry): stored result, no second debit"
post "$OPTOK" "$CALL" "$SID"

hdr "7. a different high-risk transfer: the op-bound token does not cover it -> new 403"
post "$OPTOK" '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"transfer","arguments":{"from_account":"savings","pix_key":"dan@pix.example","amount":2000}}}' "$SID"

hdr "8. badly-ordered tool: commits item 1, then needs step-up -> guard refuses the 403, partial result in-band"
post "$BASE" '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"naive_batch_transfer","arguments":{"from_account":"checking","items":[{"pix_key":"bob@pix.example","amount":20},{"pix_key":"zed@pix.example","amount":900}]}}}' "$SID"

hdr "9. balances"
post "$BASE" '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_accounts","arguments":{}}}' "$SID"
