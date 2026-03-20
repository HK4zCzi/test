#!/bin/bash
BASE="http://localhost:8080"

echo "════════════════════════════════════════════════════"
echo "  DAY 3 TESTS"
echo "════════════════════════════════════════════════════"

# Create test assets
DOMAIN_ID=$(curl -s -X POST $BASE/assets/single \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com","type":"domain"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

IP_ID=$(curl -s -X POST $BASE/assets/single \
  -H "Content-Type: application/json" \
  -d '{"name":"8.8.8.8","type":"ip"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "Domain: $DOMAIN_ID"
echo "IP: $IP_ID"

echo ""
echo "── Bài 1: Scan API ─────────────────────────────────"

for TYPE in dns ssl waf tech headers cors; do
  echo -n "POST /scan $TYPE → "
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/assets/$DOMAIN_ID/scan" \
    -H "Content-Type: application/json" -d "{\"scan_type\":\"$TYPE\"}")
  [ "$STATUS" = "202" ] && echo "✅ 202" || echo "❌ $STATUS"
done

for TYPE in ip asn shodan port; do
  echo -n "POST /scan $TYPE (IP asset) → "
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/assets/$IP_ID/scan" \
    -H "Content-Type: application/json" -d "{\"scan_type\":\"$TYPE\"}")
  [ "$STATUS" = "202" ] && echo "✅ 202" || echo "❌ $STATUS"
done

echo -n "IP scan on domain → should be 400: "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/assets/$DOMAIN_ID/scan" \
  -H "Content-Type: application/json" -d '{"scan_type":"ip"}')
[ "$STATUS" = "400" ] && echo "✅ 400 (correct)" || echo "❌ $STATUS"

echo -n "domain_full group → "
RES=$(curl -s -X POST "$BASE/assets/$DOMAIN_ID/scan" \
  -H "Content-Type: application/json" -d '{"scan_type":"domain_full"}')
JOBS=$(echo $RES | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jobs_started',0))")
echo "✅ $JOBS jobs started"

echo -n "ip_full group → "
RES=$(curl -s -X POST "$BASE/assets/$IP_ID/scan" \
  -H "Content-Type: application/json" -d '{"scan_type":"ip_full"}')
JOBS=$(echo $RES | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('jobs_started',0))")
echo "✅ $JOBS jobs started"

echo ""
echo "── Bài 2: Tests ─────────────────────────────────────"
cd "$(dirname "$0")/../../.." 2>/dev/null || cd ~/Desktop/dev
pytest tests/ -v --tb=short -q 2>&1 | tail -5

echo ""
echo "── Bài 3: Frontend ──────────────────────────────────"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000)
[ "$STATUS" = "200" ] && echo "✅ Frontend running at :3000" || echo "❌ Frontend not accessible"

echo ""
echo "── Bài 5: Docker health ─────────────────────────────"
curl -s $BASE/health | python3 -m json.tool

echo ""
echo "── Bài 6: Export ────────────────────────────────────"
echo -n "Export JSON → "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/assets/$DOMAIN_ID/export")
[ "$STATUS" = "200" ] && echo "✅ 200" || echo "❌ $STATUS"

echo -n "Export CSV → "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/assets/$DOMAIN_ID/export?format=csv")
[ "$STATUS" = "200" ] && echo "✅ 200" || echo "❌ $STATUS"

# Cleanup
curl -s -X DELETE "$BASE/assets/batch?ids=$DOMAIN_ID,$IP_ID" > /dev/null

echo ""
echo "✅ Day 3 tests done!"
