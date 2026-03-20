#!/bin/bash
# ── End-to-End Test Script ─────────────────────────────────────
# Tests the full ExoEth governance pipeline locally
#
# Prerequisites: All services running (./scripts/start-local.sh)

set -euo pipefail

BASE="http://localhost"
PASS=0
FAIL=0

test_endpoint() {
  local method="$1" url="$2" name="$3" body="${4:-}"
  local status

  if [ "$method" = "GET" ]; then
    status=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
  else
    status=$(curl -sf -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$body" "$url" 2>/dev/null || echo "000")
  fi

  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    echo "  ✅ $name ($status)"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $name (HTTP $status)"
    FAIL=$((FAIL + 1))
  fi
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ExoEth Platform — End-to-End Test Suite                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "── Health Checks ──────────────────────────────────────────"
test_endpoint GET "$BASE:3000/health" "Gateway API"
test_endpoint GET "$BASE:3001/health" "Identity Service"
test_endpoint GET "$BASE:3002/health" "Consent Service"
test_endpoint GET "$BASE:3003/health" "Governance Engine"
test_endpoint GET "$BASE:3004/health" "Decision Forge"
test_endpoint GET "$BASE:3005/health" "CrossCheck Adapter"
test_endpoint GET "$BASE:3006/health" "Provenance Writer"
test_endpoint GET "$BASE:3007/health" "Audit API"
test_endpoint GET "$BASE:3008/health" "Notification Service"
test_endpoint GET "$BASE:3009/health" "Policy Distribution"
test_endpoint GET "$BASE:3010/health" "Syntaxis Orchestrator"
test_endpoint GET "$BASE:3011/health" "CAIP Engine"

echo ""
echo "── Identity Resolution (0dentity) ─────────────────────────"
test_endpoint POST "$BASE:3001/resolve" "Resolve identity" \
  '{"walletAddress":"0xAlice00000000000000000000000000000000"}'

echo ""
echo "── Consent Verification (LiveSafe) ────────────────────────"
test_endpoint POST "$BASE:3002/resolve" "Resolve consent" \
  '{"assetId":"governance_evaluation"}'

echo ""
echo "── Governance Engine ──────────────────────────────────────"
test_endpoint POST "$BASE:3003/evaluate" "Evaluate proposal" \
  '{"proposal":{"proposalId":"test-001","walletAddress":"0xAlice00","target":"0x0","payload":"test"},"identity":{"odentityId":"od-Alice0"},"consent":{"consentId":"c-1","allowedUses":["governance_evaluation"]},"crosscheck":{"consensus":true,"riskScore":0.1}}'

test_endpoint POST "$BASE:3003/create-decision" "Create decision" \
  '{"tenant_id":"exoeth-foundation","title":"E2E Test Decision","decision_class":"Operational","constitution_hash":"0000000000000000000000000000000000000000000000000000000000000000","constitution_version":[1,0,0],"author":"did:exo:alice","eligible_voters":["did:exo:alice","did:exo:bob"],"minimum_participants":2,"approval_threshold_pct":51}'

test_endpoint GET "$BASE:3003/transitions/Created" "Valid transitions"

echo ""
echo "── Decision Forge ─────────────────────────────────────────"
test_endpoint POST "$BASE:3004/deliberate" "Forge deliberation" \
  '{"proposalId":"test-001","governanceDecision":{"governanceCaseId":"case-001","decision":"approved","reasons":["all_gates_passed"],"policyVersion":"v0"}}'

echo ""
echo "── CrossChecked Consensus ─────────────────────────────────"
test_endpoint POST "$BASE:3005/check" "CrossCheck consensus" \
  '{"proposal":{"proposalId":"test-001"},"identity":{"odentityId":"od-Alice0"}}'

echo ""
echo "── Provenance Writer ──────────────────────────────────────"
test_endpoint POST "$BASE:3006/write" "Write provenance receipt" \
  '{"eventType":"e2e_test","correlationId":"test-corr-001","payload":{"test":true}}'

test_endpoint GET "$BASE:3006/receipts" "List receipts"

echo ""
echo "── Audit API ──────────────────────────────────────────────"
test_endpoint POST "$BASE:3007/record" "Record audit entry" \
  '{"eventType":"e2e_test","correlationId":"test-corr-001","actor":"e2e-test","tenant":"exoeth-foundation"}'

test_endpoint GET "$BASE:3007/log" "Audit log"

echo ""
echo "── Policy Distribution (LegalDyne) ────────────────────────"
test_endpoint GET "$BASE:3009/current" "Current policy"

echo ""
echo "── Syntaxis Orchestrator ──────────────────────────────────"
test_endpoint GET "$BASE:3010/modules" "List modules"
test_endpoint GET "$BASE:3010/situation-room" "Situation room"

test_endpoint POST "$BASE:3010/onboard" "PACE onboard executive" \
  '{"name":"E2E Test User","email":"e2e@test.com","walletAddress":"0xe2e0000000000000000000000000000000000000","role":"cto","organization":"TestCo"}'

echo ""
echo "── Full Workflow Execution ────────────────────────────────"
WORKFLOW_RESULT=$(curl -sf -X POST -H "Content-Type: application/json" -d '{
  "title": "E2E Test: Full Governance Pipeline",
  "walletAddress": "0xAlice00000000000000000000000000000000",
  "decisionClass": "Standard",
  "moduleId": "decision-forum",
  "content": "End-to-end test of the complete ExoChain governance pipeline",
  "target": "0x0000000000000000000000000000000000000001"
}' "$BASE:3010/workflow/execute" 2>/dev/null || echo '{"error":"failed"}')

if echo "$WORKFLOW_RESULT" | grep -q '"status":"complete"'; then
  echo "  ✅ Full workflow execution — COMPLETE"
  PASS=$((PASS + 1))
  DECISION_STATUS=$(echo "$WORKFLOW_RESULT" | grep -o '"status":"[^"]*"' | head -2 | tail -1 | cut -d'"' -f4)
  echo "     Decision: $DECISION_STATUS"
else
  echo "  ❌ Full workflow execution — FAILED"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "── CAIP Assessment ────────────────────────────────────────"
test_endpoint POST "$BASE:3011/assess" "CTO Assessment" \
  '{"cto_name":"Jane Doe","walletAddress":"0xCAIP000000000000000000000000000000000000","company":{"name":"TestCo","team_size":25,"has_repeatable_sales":true,"has_multiple_modules":true,"has_formal_arch_function":false,"investor_type":"VC","ai_native":true},"cto_profile":{"role_type":"hired_cto"},"engagement_purpose":"fractional_engagement"}'

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
  echo "  🎉 All tests passed! ExoChain governance pipeline is operational."
fi

exit $FAIL
