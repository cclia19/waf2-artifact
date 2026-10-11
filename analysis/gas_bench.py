#!/usr/bin/env python3
"""
WAF-2 registry: functional tests + DETERMINISTIC EVM gas measurement.

Tags are derived from a fixed seed, not os.urandom, so calldata gas (16 gas per
non-zero byte, 4 per zero byte) is reproducible run to run. Every figure printed
here is executed on py-evm, and re-running this script reproduces it exactly.
"""
import json, os, statistics, random, time
import solcx
from web3 import Web3, EthereumTesterProvider
from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import keccak
from eth_abi.packed import encode_packed

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "contracts", "WAFRegistry.sol")
RNG = random.Random(20261011)          # fixed seed -> deterministic calldata

def cid(i):  return RNG.randbytes(32)
def hcid(c): return keccak(c)
def tag_for(issuer, c):
    return keccak(encode_packed(["address", "bytes32"], [issuer, hcid(c)]))

solcx.set_solc_version("0.8.24")
compiled = solcx.compile_files([SRC], output_values=["abi", "bin"],
                               optimize=True, optimize_runs=200, solc_version="0.8.24")
key = [k for k in compiled if k.endswith(":WAFRegistry")][0]
ABI, BIN = compiled[key]["abi"], compiled[key]["bin"]
print(f"compiled WAFRegistry v2  ({len(BIN)//2} bytes init+runtime bytecode)")

backend = PyEVMBackend.from_mnemonic(
    "test test test test test test test test test test test junk", num_accounts=10)
w3 = Web3(EthereumTesterProvider(EthereumTester(backend)))
a = w3.eth.accounts
ADMIN1, ADMIN2, ADMIN3 = a[0], a[1], a[2]
AP_HOME, AP_OFFICE, AP_CAFE = a[3], a[4], a[5]
OUTSIDER = a[6]
GAS, FAIL = {}, []

def send(fn, sender, label=None, gas=8_000_000):
    r = w3.eth.wait_for_transaction_receipt(fn.transact({"from": sender, "gas": gas}))
    assert r.status == 1, f"reverted: {label}"
    if label: GAS[label] = r.gasUsed
    return r

def gasof(fn, sender, gas=30_000_000):
    return w3.eth.wait_for_transaction_receipt(fn.transact({"from": sender, "gas": gas})).gasUsed

def expect_revert(fn, sender, what):
    try:
        tx = fn.transact({"from": sender, "gas": 8_000_000})
    except Exception:
        print(f"  ok  rejected: {what}"); return
    if w3.eth.wait_for_transaction_receipt(tx).status == 0:
        print(f"  ok  rejected: {what}"); return
    FAIL.append(what); print(f"  !!  SHOULD HAVE REVERTED: {what}")

def ok(cond, what):
    if cond: print(f"  ok  {what}")
    else: FAIL.append(what); print(f"  !!  FAILED: {what}")

# ---------------------------------------------------------------- deploy
C = w3.eth.contract(abi=ABI, bytecode=BIN)
r = w3.eth.wait_for_transaction_receipt(
    C.constructor([ADMIN1, ADMIN2, ADMIN3], 2).transact({"from": ADMIN1, "gas": 8_000_000}))
GAS["deploy"] = r.gasUsed
reg = w3.eth.contract(address=r.contractAddress, abi=ABI)

# constructor must validate quorum against the DE-DUPLICATED admin count
try:
    bad = w3.eth.wait_for_transaction_receipt(
        C.constructor([ADMIN1, ADMIN1, ADMIN1], 3).transact({"from": ADMIN1, "gas": 8_000_000}))
    ok(bad.status == 0, "constructor rejects unreachable quorum from duplicate admins")
except Exception:
    print("  ok  constructor rejects unreachable quorum from duplicate admins")

RCOI = keccak(text="waf:consortium:utar-demo")[:32]
DAY = 24 * 3600

print("\n--- governance ---")
send(reg.functions.admitMember(AP_HOME, RCOI, 0), ADMIN1, "admitMember_approval1")
ok(reg.functions.members(AP_HOME).call()[3] is False, "1-of-3 does not admit (quorum=2)")
send(reg.functions.admitMember(AP_HOME, RCOI, 0), ADMIN2, "admitMember_approval2_exec")
ok(reg.functions.members(AP_HOME).call()[3] is True, "2-of-3 admits")
for ap in (AP_OFFICE, AP_CAFE):
    reg.functions.admitMember(ap, RCOI, 0).transact({"from": ADMIN1, "gas": 8_000_000})
    reg.functions.admitMember(ap, RCOI, 0).transact({"from": ADMIN2, "gas": 8_000_000})
expect_revert(reg.functions.admitMember(OUTSIDER, RCOI, 0), OUTSIDER, "non-admin cannot admit")

print("\n--- governance: approval replay must NOT collapse m-of-n to 1-of-n ---")
reg.functions.removeMember(AP_CAFE).transact({"from": ADMIN1, "gas": 8_000_000})
send(reg.functions.removeMember(AP_CAFE), ADMIN2, "removeMember")
ok(reg.functions.members(AP_CAFE).call()[3] is False, "member removed by quorum")
# a single admin re-proposing the IDENTICAL admit action must not execute
reg.functions.admitMember(AP_CAFE, RCOI, 0).transact({"from": ADMIN1, "gas": 8_000_000})
ok(reg.functions.members(AP_CAFE).call()[3] is False,
   "single admin CANNOT re-admit after a prior quorum (approval replay closed)")
reg.functions.admitMember(AP_CAFE, RCOI, 0).transact({"from": ADMIN2, "gas": 8_000_000})
ok(reg.functions.members(AP_CAFE).call()[3] is True, "fresh quorum re-admits")

print("\n--- admin key rotation ---")
reg.functions.addAdmin(a[7]).transact({"from": ADMIN1, "gas": 8_000_000})
send(reg.functions.addAdmin(a[7]), ADMIN2, "addAdmin")
ok(reg.functions.isAdmin(a[7]).call(), "admin added by quorum")
reg.functions.removeAdmin(a[7]).transact({"from": ADMIN1, "gas": 8_000_000})
send(reg.functions.removeAdmin(a[7]), ADMIN2, "removeAdmin")
ok(not reg.functions.isAdmin(a[7]).call(), "admin removed by quorum")

print("\n--- issuance ---")
now = w3.eth.get_block("latest").timestamp
c0 = cid(0); t0 = tag_for(AP_HOME, c0)
send(reg.functions.issueCredential(hcid(c0), now + DAY, 3), AP_HOME, "issueCredential")
v, loa, iss = reg.functions.check(t0).call()
ok(v and loa == 3 and iss == AP_HOME, "credential validates")
ok(reg.functions.check(t0).call({"from": AP_CAFE})[0],
   "CROSS-DOMAIN: credential from AP_HOME validates at AP_CAFE")
expect_revert(reg.functions.issueCredential(hcid(cid(1)), now + DAY, 1),
              OUTSIDER, "non-member cannot issue")
expect_revert(reg.functions.issueCredential(hcid(cid(2)), now + 400 * DAY, 1),
              AP_HOME, "credential lifetime is capped on-chain")

print("\n--- tag squatting (issuer-scoped namespace) ---")
cx = cid(3)
# AP_OFFICE front-runs with the SAME hcid, trying to occupy AP_HOME's slot
reg.functions.issueCredential(hcid(cx), now + DAY, 255).transact(
    {"from": AP_OFFICE, "gas": 8_000_000})
send(reg.functions.issueCredential(hcid(cx), now + DAY, 2), AP_HOME)
v2, loa2, iss2 = reg.functions.check(tag_for(AP_HOME, cx)).call()
ok(v2 and iss2 == AP_HOME and loa2 == 2,
   "issuer-scoped tags defeat front-running: AP_HOME's issuance is unaffected")
ok(reg.functions.check(tag_for(AP_OFFICE, cx)).call()[2] == AP_OFFICE,
   "the squatter's entry lands in its OWN namespace and cannot impersonate")

print("\n--- bitmap revocation is namespaced to the caller ---")
cB = cid(4); tB = tag_for(AP_HOME, cB)
reg.functions.issueCredential(hcid(cB), now + DAY, 1).transact({"from": AP_HOME, "gas": 8_000_000})
ep = reg.functions.issuerEpoch(AP_HOME).call()
slot = reg.functions.credentials(tB).call()[3]
# a hostile peer member blankets the bitmap; it must not affect AP_HOME
reg.functions.revokeBitmap(ep, slot >> 8, (1 << 256) - 1).transact(
    {"from": AP_OFFICE, "gas": 8_000_000})
ok(reg.functions.check(tB).call()[0],
   "a malicious member CANNOT revoke another member's credentials via bitmap")
send(reg.functions.revokeBitmap(ep, slot >> 8, 1 << (slot & 0xff)), AP_HOME, "revokeBitmap_single")
ok(not reg.functions.check(tB).call()[0],
   "check() ENFORCES bitmap revocation (not merely records it)")

print("\n--- per-credential revocation, expiry, ejection cascade ---")
send(reg.functions.revoke(t0), AP_HOME, "revoke")
ok(not reg.functions.check(t0).call()[0], "revoked credential fails check")
cP = cid(5); tP = tag_for(AP_OFFICE, cP)
reg.functions.issueCredential(hcid(cP), now + DAY, 2).transact({"from": AP_OFFICE, "gas": 8_000_000})
expect_revert(reg.functions.revoke(tP), AP_CAFE, "peer member cannot revoke another's credential")
send(reg.functions.revoke(tP), ADMIN1, "adminRevoke")

cE = cid(6); tE = tag_for(AP_HOME, cE)
reg.functions.issueCredential(hcid(cE), now + 60, 1).transact({"from": AP_HOME, "gas": 8_000_000})
ok(reg.functions.check(tE).call()[0], "short-lived credential valid before expiry")
backend.time_travel(now + 120); w3.provider.ethereum_tester.mine_block()
ok(not reg.functions.check(tE).call()[0], "credential expires with no revocation transaction")

# AP_OFFICE blanketed its OWN epoch-0 bitmap during the griefing test above,
# so roll it to a fresh namespace before testing the ejection cascade.
reg.functions.rollEpoch().transact({"from": AP_OFFICE, "gas": 8_000_000})
nowt = w3.eth.get_block("latest").timestamp
cC = cid(7); tC = tag_for(AP_OFFICE, cC)
rc = w3.eth.wait_for_transaction_receipt(
    reg.functions.issueCredential(hcid(cC), nowt + DAY, 1).transact(
        {"from": AP_OFFICE, "gas": 8_000_000}))
ok(rc.status == 1, "AP_OFFICE issuance succeeds")
ok(reg.functions.check(tC).call()[0], "credential valid before issuer ejection")
reg.functions.removeMember(AP_OFFICE).transact({"from": ADMIN1, "gas": 8_000_000})
reg.functions.removeMember(AP_OFFICE).transact({"from": ADMIN2, "gas": 8_000_000})
ok(not reg.functions.check(tC).call()[0], "ejecting a member invalidates its credentials")

# ============================================================ GAS
print("\n--- bulk issuance scaling ---")
BATCH = {}
for n in (1, 10, 50, 100):
    nowt = w3.eth.get_block("latest").timestamp
    cs = [cid(i) for i in range(n)]
    g = gasof(reg.functions.issueBatch([hcid(c) for c in cs], nowt + DAY, 1), AP_HOME)
    BATCH[n] = g
    print(f"  issueBatch n={n:>4}: {g:>9,} gas  ({g/n:>9,.0f} per credential)")

print("\n--- revocation strategies, 256 credentials ---")
N = 256
nowt = w3.eth.get_block("latest").timestamp
reg.functions.rollEpoch().transact({"from": AP_HOME, "gas": 8_000_000})
ep = reg.functions.issuerEpoch(AP_HOME).call()
cs = [cid(i) for i in range(N)]
tags = [tag_for(AP_HOME, c) for c in cs]
reg.functions.issueBatch([hcid(c) for c in cs], nowt + DAY, 1).transact({"from": AP_HOME, "gas": 30_000_000})

g_ind = gasof(reg.functions.revokeBatch(tags), AP_HOME)
print(f"  A. per-credential (revokeBatch)        : {g_ind:>9,} gas  ({g_ind/N:>8,.0f}/cred)")
print(f"     NOTE: this path also writes revokedAt (a cold zero->non-zero SSTORE,")
print(f"     retained for revocation-latency studies) and emits one LOG3 per")
print(f"     credential. Both are absent from the bitmap path. The ratio below")
print(f"     is therefore an upper bound on the saving attributable to bitmapping.")

# contiguous best case: 256 slots issued consecutively share one word
reg.functions.rollEpoch().transact({"from": AP_HOME, "gas": 8_000_000})
ep2 = reg.functions.issuerEpoch(AP_HOME).call()
nowt = w3.eth.get_block("latest").timestamp
cs2 = [cid(i) for i in range(N)]
tags2 = [tag_for(AP_HOME, c) for c in cs2]
reg.functions.issueBatch([hcid(c) for c in cs2], nowt + DAY, 1).transact({"from": AP_HOME, "gas": 30_000_000})
g_bm = gasof(reg.functions.revokeBitmap(ep2, 0, (1 << 256) - 1), AP_HOME)
ok(not reg.functions.check(tags2[0]).call()[0] and not reg.functions.check(tags2[255]).call()[0],
   "contiguous bitmap revocation enforced by check()")
print(f"  B. bitmap, CONTIGUOUS (1 word)         : {g_bm:>9,} gas  ({g_bm/N:>8,.0f}/cred)")

# scattered worst case: 256 credentials in 256 different words
reg.functions.rollEpoch().transact({"from": AP_HOME, "gas": 8_000_000})
ep3 = reg.functions.issuerEpoch(AP_HOME).call()
words = list(range(N)); bits = [1] * N
g_bms = gasof(reg.functions.revokeBitmapBatch(ep3, words, bits), AP_HOME)
print(f"  C. bitmap, SCATTERED (256 words)       : {g_bms:>9,} gas  ({g_bms/N:>8,.0f}/cred)")

g_root = gasof(reg.functions.publishRevocationRoot(ep2, keccak(b"".join(sorted(tags2)))), AP_HOME)
print(f"  D. Merkle root (advisory, 1 word)      : {g_root:>9,} gas  ({g_root/N:>8,.0f}/cred at n=256)")
print(f"\n  contiguous bitmap vs per-credential : {g_ind/g_bm:.1f}x cheaper")
print(f"  scattered  bitmap vs per-credential : {g_ind/g_bms:.1f}x cheaper")
print(f"  Merkle root vs per-credential       : {g_ind/g_root:.1f}x cheaper")

print("\n--- authorisation hot path ---")
t = []
for _ in range(200):
    s = time.perf_counter(); reg.functions.check(tags[0]).call(); t.append((time.perf_counter()-s)*1000)
t.sort()
print(f"  check() local eth_call: median {statistics.median(t):.3f} ms (includes the Python")
print(f"  web3 RPC stack; the EVM-level cost is five cold SLOADs). Reported only as an")
print(f"  upper bound — it is NOT comparable to a RADIUS round trip.")

print("\n" + "=" * 70)
print("MEASURED GAS (solc 0.8.24, optimiser 200 runs, py-evm, seeded tags)")
print("=" * 70)
for k, v in GAS.items(): print(f"  {k:<34} {v:>10,}")

json.dump({"solc": "0.8.24", "optimizer_runs": 200, "seed": 20261011,
           "bytecode_bytes": len(BIN)//2, "single_op_gas": GAS, "issue_batch_gas": BATCH,
           "revocation_256": {"per_credential": g_ind, "bitmap_contiguous": g_bm,
                              "bitmap_scattered": g_bms, "merkle_root": g_root},
           "ratios": {"contiguous": g_ind/g_bm, "scattered": g_ind/g_bms,
                      "merkle": g_ind/g_root}},
          open(os.path.join(HERE, "gas_results.json"), "w"), indent=2)

print(f"\n{'ALL FUNCTIONAL TESTS PASSED' if not FAIL else 'FAILURES: ' + str(FAIL)}")
