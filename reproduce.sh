#!/usr/bin/env bash
# WAF-2 artefact — reproduce every result in the paper.
#
#   ./reproduce.sh              everything
#   ./reproduce.sh gas          Tables III-IV only        (~30 s)
#   ./reproduce.sh proverif     Table II and section VI   (~2 min)
#   ./reproduce.sh consortium   Table V and Figure 1      (~15 min, starts geth)
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
WHAT="${1:-all}"
FAILED=0

bar() { printf '\n%s\n  %s\n%s\n' "$(printf '=%.0s' {1..70})" "$1" "$(printf '=%.0s' {1..70})"; }
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }

# ----------------------------------------------------------------- preflight
bar "Preflight"
command -v python3 >/dev/null && ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2)" \
  || { bad "python3 not found"; exit 1; }
python3 -c "import web3, solcx, numpy, scipy, matplotlib" 2>/dev/null \
  && ok "python dependencies present" \
  || { bad "missing deps — run: pip install -r requirements.txt"; exit 1; }

if [ "$WHAT" = "all" ] || [ "$WHAT" = "consortium" ]; then
  if command -v geth >/dev/null; then
    GV="$(geth version 2>/dev/null | awk '/^Version:/{print $2}')"
    case "$GV" in
      1.13.*) ok "geth $GV (Clique supported)" ;;
      *) bad "geth $GV — Clique was REMOVED in v1.14.0. Install v1.13.x." ;;
    esac
  else
    bad "geth not found — needed for the consortium benchmark"
  fi
fi

if [ "$WHAT" = "all" ] || [ "$WHAT" = "proverif" ]; then
  command -v proverif >/dev/null && ok "proverif $(proverif -help 2>&1 | head -1 | awk '{print $2}')" \
    || bad "proverif not found — https://bblanche.gitlabpages.inria.fr/proverif/"
fi

# ----------------------------------------------------------- gas (Tables III-IV)
if [ "$WHAT" = "all" ] || [ "$WHAT" = "gas" ]; then
  bar "On-chain cost — Tables III and IV"
  if python3 -I analysis/gas_bench.py; then
    ok "gas benchmark complete"
    python3 - <<'PY'
import json, os, sys
new = json.load(open("analysis/gas_results.json"))
ref = json.load(open("results/gas_results.json"))
diffs = [(k, ref["single_op_gas"][k], new["single_op_gas"][k])
         for k in ref["single_op_gas"]
         if ref["single_op_gas"][k] != new["single_op_gas"].get(k)]
if diffs:
    print("  NOTE: gas differs from the published run (contract was modified?):")
    for k, a, b in diffs:
        print(f"        {k}: published {a:,} -> yours {b:,}")
else:
    print("  determinism check: gas matches the published run exactly")
PY
  else
    bad "gas benchmark failed"
  fi
fi

# ------------------------------------------------- proverif (Table II, sec. VI)
if [ "$WHAT" = "all" ] || [ "$WHAT" = "proverif" ]; then
  bar "Formal verification — Table II and Section VI"
  # waf2_malicious_member.pv is EXPECTED to report two false results; that is the
  # documented inherent limitation, not a regression. See README.
  for f in proverif/waf2_core.pv proverif/waf2_fs.pv proverif/waf2_kci.pv \
           proverif/waf2_revocation.pv proverif/waf2_malicious_member.pv; do
    printf '\n  --- %s\n' "$(basename "$f")"
    if out="$(proverif -in pitype "$f" 2>&1)"; then
      echo "$out" | grep -E '^RESULT' | sed 's/^/      /'
    else
      bad "proverif failed on $f"
    fi
  done
  cat <<'NOTE'

  How to read these:
    waf2_core / fs / kci  : every RESULT should be "true", EXCEPT the
                            non-vacuity check "not event(ServerCompletes...)"
                            which must be "false" (meaning the honest run IS
                            reachable — a vacuous model proves nothing).
    waf2_revocation       : AcceptedE1(revoked) true (unreachable);
                            AcceptedE0(revoked) and AcceptedE1(good) false
                            (both reachable).
    waf2_malicious_member : session-key secrecy and device-side agreement are
                            EXPECTED to be false. That is the documented
                            inherent limitation. Server-side agreement,
                            nonce secrecy and authorisation must still hold.
NOTE
fi

# --------------------------------------- consortium (Table V, Figure 1)
if [ "$WHAT" = "all" ] || [ "$WHAT" = "consortium" ]; then
  bar "Revocation propagation on a live consortium — Table V and Figure 1"
  echo "  Starting 4, 7, 10 and 13 geth nodes in turn. This takes ~15 minutes."
  if python3 -I -u harness/consortium_bench.py 4 7 10 13; then
    ok "consortium benchmark complete"
    python3 -I analysis/consortium_analysis.py && ok "analysis and Figure 1 regenerated" \
      || bad "analysis failed"
  else
    bad "consortium benchmark failed"
  fi
  pkill -x geth 2>/dev/null || true
fi

bar "Done"
if [ "$FAILED" -eq 0 ]; then
  echo "  All requested steps completed."
else
  echo "  One or more steps failed — see above."
fi
echo "  Published reference outputs for comparison are in results/"
exit "$FAILED"
