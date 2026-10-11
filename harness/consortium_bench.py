#!/usr/bin/env python3
"""
WAF-2: revocation-propagation measurement on a REAL multi-node consortium.

Stands up an N-node permissioned Clique proof-of-authority chain with
go-ethereum v1.13.15 (the last release that supports Clique; it was removed in
v1.14.0), deploys the WAFRegistry contract, and measures how long a revocation
takes to become observable at every other access point in the consortium.

This is the quantity the architecture actually depends on: the authorisation
check itself is a local read, so what bounds the security of the system is how
quickly a revocation reaches the replicas. It is measured here directly rather
than inferred from a curve fit.

Reported per revocation:
  t_inclusion   submit -> transaction receipt at the issuing node
  t_propagation receipt -> `check()` returns false at a given remote node
  t_total       submit -> revoked everywhere

Usage:  python3 -I consortium_bench.py 4 7 10
"""
import json, os, shutil, signal, socket, subprocess, sys, time, statistics
import solcx
from web3 import Web3, HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account
from eth_utils import keccak
from eth_abi.packed import encode_packed

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "contracts", "WAFRegistry.sol")
RUN = os.path.join(HERE, "run")
CHAIN_ID = 91337
PERIOD = 2              # Clique block period, seconds
REVOCATIONS = 20        # measured revocations per consortium size
BASE_P2P, BASE_HTTP, BASE_AUTH = 31000, 18500, 19500

# Deterministic signer keys: this benchmark must be reproducible.
KEYS = [keccak(text=f"waf2-consortium-signer-{i}").hex() for i in range(16)]
ACCTS = [Account.from_key(bytes.fromhex(k)) for k in KEYS]


def free_port(p):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", p)) != 0


def build_genesis(n, path):
    signers = [a.address[2:].lower() for a in ACCTS[:n]]
    extradata = "0x" + "00" * 32 + "".join(signers) + "00" * 65
    alloc = {a.address[2:]: {"balance": "0x200000000000000000000000"} for a in ACCTS[:n]}
    g = {
        "config": {
            "chainId": CHAIN_ID, "homesteadBlock": 0, "eip150Block": 0,
            "eip155Block": 0, "eip158Block": 0, "byzantiumBlock": 0,
            "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
            "berlinBlock": 0, "londonBlock": 0,
            "clique": {"period": PERIOD, "epoch": 30000},
        },
        "difficulty": "1", "gasLimit": "0x1C9C380",
        "extradata": extradata, "alloc": alloc,
    }
    json.dump(g, open(path, "w"))


def start_node(i, datadir, genesis):
    subprocess.run(["geth", "--datadir", datadir, "init", genesis],
                   check=True, capture_output=True)
    ks = os.path.join(datadir, "keystore")
    os.makedirs(ks, exist_ok=True)
    pw = os.path.join(datadir, "pw")
    open(pw, "w").write("waf2")
    enc = Account.encrypt(bytes.fromhex(KEYS[i]), "waf2")
    json.dump(enc, open(os.path.join(ks, f"key{i}.json"), "w"))

    log = open(os.path.join(datadir, "geth.log"), "w")
    proc = subprocess.Popen([
        "geth", "--datadir", datadir, "--networkid", str(CHAIN_ID),
        "--port", str(BASE_P2P + i), "--nodiscover",
        "--http", "--http.addr", "127.0.0.1", "--http.port", str(BASE_HTTP + i),
        "--http.api", "eth,net,web3,admin,miner,personal,txpool",
        "--authrpc.port", str(BASE_AUTH + i),
        "--mine", "--miner.etherbase", ACCTS[i].address,
        "--unlock", ACCTS[i].address, "--password", pw,
        "--allow-insecure-unlock", "--ipcdisable",
        "--verbosity", "2", "--syncmode", "full", "--gcmode", "archive",
        "--maxpeers", "64",
    ], stdout=log, stderr=subprocess.STDOUT)
    return proc


def w3_for(i):
    w = Web3(HTTPProvider(f"http://127.0.0.1:{BASE_HTTP+i}",
                          request_kwargs={"timeout": 20}))
    w.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w


def wait_rpc(w, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            w.eth.block_number
            return True
        except Exception:
            time.sleep(0.3)
    return False


def run_size(n, abi, bytecode):
    print(f"\n{'='*66}\n  CONSORTIUM SIZE n = {n} access points\n{'='*66}")
    root = os.path.join(RUN, f"n{n}")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    genesis = os.path.join(root, "genesis.json")
    build_genesis(n, genesis)

    procs = [start_node(i, os.path.join(root, f"node{i}"), genesis) for i in range(n)]
    w3s = [w3_for(i) for i in range(n)]
    for i, w in enumerate(w3s):
        if not wait_rpc(w):
            raise RuntimeError(f"node {i} RPC did not come up")
    print(f"  {n} nodes up")

    # full mesh peering
    enodes = []
    for i, w in enumerate(w3s):
        ni = w.provider.make_request("admin_nodeInfo", [])["result"]
        enodes.append(ni["enode"].replace("127.0.0.1", "127.0.0.1"))
    for i, w in enumerate(w3s):
        for j, e in enumerate(enodes):
            if i != j:
                w.provider.make_request("admin_addPeer", [e])
    # wait for the mesh to form and blocks to be produced
    t0 = time.time()
    while time.time() - t0 < 90:
        peers = [w.net.peer_count for w in w3s]
        heights = [w.eth.block_number for w in w3s]
        if min(peers) >= n - 1 and min(heights) >= 2:
            break
        time.sleep(1)
    print(f"  peers={peers}  heights={heights}")
    if min(peers) < n - 1:
        raise RuntimeError(f"mesh incomplete: {peers}")

    # deploy from node 0
    w0 = w3s[0]
    deployer = ACCTS[0]
    C = w0.eth.contract(abi=abi, bytecode=bytecode)
    admins = [a.address for a in ACCTS[:min(3, n)]]
    quorum = 1
    addr = None
    for attempt in range(5):
        tx = C.constructor(admins, quorum).build_transaction({
            "from": deployer.address,
            "nonce": w0.eth.get_transaction_count(deployer.address),
            "gas": 6_000_000, "gasPrice": w0.eth.gas_price, "chainId": CHAIN_ID})
        signed = Account.sign_transaction(tx, deployer.key)
        h = w0.eth.send_raw_transaction(signed.raw_transaction)
        rc = w0.eth.wait_for_transaction_receipt(h, timeout=120)
        if rc.status != 1:
            raise RuntimeError("deployment reverted")
        cand = rc.contractAddress
        # survive a possible reorg: require code to persist locally
        t0 = time.time(); okc = False
        while time.time() - t0 < 25:
            if len(w0.eth.get_code(cand)) > 0 and w0.eth.block_number - rc.blockNumber >= 2:
                okc = True; break
            time.sleep(0.4)
        if okc:
            addr = cand
            print(f"  WAFRegistry deployed at {addr} (block {rc.blockNumber}, attempt {attempt+1})")
            break
        print(f"  deploy attempt {attempt+1} lost to a reorg; retrying")
    if addr is None:
        raise RuntimeError("deployment did not persist after 5 attempts")

    # Wait for the deployment to replicate AND settle. Clique can reorg a
    # just-sealed block, so we require code present at every node and a few
    # confirmations before transacting.
    t0 = time.time()
    while time.time() - t0 < 120:
        try:
            codes = [len(w.eth.get_code(addr)) for w in w3s]
            depth = w0.eth.block_number - rc.blockNumber
            if min(codes) > 0 and depth >= 3:
                break
        except Exception:
            pass
        time.sleep(0.5)
    codes = [len(w.eth.get_code(addr)) for w in w3s]
    if min(codes) == 0:
        raise RuntimeError(f"contract code not replicated: {codes}")
    print(f"  code replicated to all {n} nodes ({codes[0]} bytes), "
          f"{w0.eth.block_number - rc.blockNumber} confirmations")

    regs = [w.eth.contract(address=addr, abi=abi) for w in w3s]

    def send(fn_factory, acct, w, gas=3_000_000, verify=None, tries=5):
        """Submit and confirm. If a Clique reorg drops the transaction, the
        state change will not be observable; resubmit until it is."""
        for _ in range(tries):
            fn = fn_factory() if callable(fn_factory) else fn_factory
            tx = fn.build_transaction({
                "from": acct.address, "nonce": w.eth.get_transaction_count(acct.address),
                "gas": gas, "gasPrice": w.eth.gas_price, "chainId": CHAIN_ID})
            sg = Account.sign_transaction(tx, acct.key)
            hh = w.eth.send_raw_transaction(sg.raw_transaction)
            rcpt = w.eth.wait_for_transaction_receipt(hh, timeout=120)
            if rcpt.status != 1:
                raise RuntimeError("transaction reverted")
            if verify is None:
                return rcpt
            t0 = time.time()
            while time.time() - t0 < 20:
                try:
                    if verify():
                        return rcpt
                except Exception:
                    pass
                time.sleep(0.3)
        raise RuntimeError("state change did not persist after retries")

    RCOI = keccak(text="waf2:consortium")[:32]
    send(lambda: regs[0].functions.admitMember(deployer.address, RCOI, 0), deployer, w0,
         verify=lambda: regs[0].functions.members(deployer.address).call()[3] is True)

    # issue credentials to revoke later
    now = w0.eth.get_block("latest").timestamp
    cids = [keccak(text=f"cred-{n}-{i}") for i in range(REVOCATIONS)]
    tags = [keccak(encode_packed(["address", "bytes32"],
                                 [deployer.address, keccak(c)])) for c in cids]
    send(lambda: regs[0].functions.issueBatch([keccak(c) for c in cids], now + 6 * 3600, 1),
         deployer, w0, gas=12_000_000,
         verify=lambda: regs[0].functions.check(tags[-1]).call()[0])
    # confirm all nodes see them valid before measuring
    t0 = time.time()
    while time.time() - t0 < 60:
        if all(r.functions.check(tags[0]).call()[0] for r in regs):
            break
        time.sleep(0.2)
    assert all(r.functions.check(tags[-1]).call()[0] for r in regs), "issuance did not converge"
    print(f"  {REVOCATIONS} credentials issued and visible at all {n} nodes")

    incl, prop, total = [], [], []
    for k, tag in enumerate(tags):
        t_submit = time.perf_counter()
        tx = regs[0].functions.revoke(tag).build_transaction({
            "from": deployer.address,
            "nonce": w0.eth.get_transaction_count(deployer.address),
            "gas": 300_000, "gasPrice": w0.eth.gas_price, "chainId": CHAIN_ID})
        s = Account.sign_transaction(tx, deployer.key)
        hh = w0.eth.send_raw_transaction(s.raw_transaction)
        w0.eth.wait_for_transaction_receipt(hh, timeout=120)
        t_incl = time.perf_counter()

        pending = set(range(1, n))
        seen = {}
        while pending and time.perf_counter() - t_incl < 60:
            for i in list(pending):
                try:
                    if not regs[i].functions.check(tag).call()[0]:
                        seen[i] = time.perf_counter()
                        pending.discard(i)
                except Exception:
                    pass
            if pending:
                time.sleep(0.02)
        if pending:
            print(f"    ! revocation {k} not seen at nodes {sorted(pending)}")
            continue
        t_all = max(seen.values()) if seen else t_incl
        incl.append(t_incl - t_submit)
        if n > 1:
            prop.extend(v - t_incl for v in seen.values())
        total.append(t_all - t_submit)
        print(f"    revocation {k+1:>2}/{REVOCATIONS}: inclusion {incl[-1]*1000:7.0f} ms  "
              f"propagation(max) {(t_all-t_incl)*1000:6.0f} ms  total {total[-1]*1000:7.0f} ms")

    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try: p.wait(timeout=20)
        except Exception: p.kill()

    def stat(x):
        if not x: return None
        xs = sorted(x)
        return {"n": len(xs), "median_ms": statistics.median(xs) * 1000,
                "mean_ms": statistics.fmean(xs) * 1000,
                "p95_ms": xs[min(len(xs) - 1, int(0.95 * len(xs)))] * 1000,
                "min_ms": xs[0] * 1000, "max_ms": xs[-1] * 1000}

    res = {"nodes": n, "clique_period_s": PERIOD,
           "inclusion": stat(incl), "propagation": stat(prop), "total": stat(total)}
    print(f"\n  n={n}: inclusion median {res['inclusion']['median_ms']:.0f} ms | "
          f"propagation median {res['propagation']['median_ms']:.0f} ms, "
          f"p95 {res['propagation']['p95_ms']:.0f} ms | "
          f"total median {res['total']['median_ms']:.0f} ms")
    return res


def main():
    sizes = [int(a) for a in sys.argv[1:]] or [4, 7, 10]
    solcx.set_solc_version("0.8.24")
    # evm_version="paris": solc 0.8.24 targets Shanghai by default and emits
    # PUSH0, which does not exist on a pre-Shanghai chain. Clique PoA chains
    # cannot enable Shanghai (it requires the withdrawals field Clique does not
    # produce), so the contract must be compiled for Paris to run here. This is
    # a real deployment constraint for permissioned Ethereum-family chains and
    # is noted in the paper.
    comp = solcx.compile_files([SRC], output_values=["abi", "bin"],
                               optimize=True, optimize_runs=200,
                               evm_version="paris", solc_version="0.8.24")
    key = [k for k in comp if k.endswith(":WAFRegistry")][0]
    abi, bc = comp[key]["abi"], comp[key]["bin"]

    os.makedirs(RUN, exist_ok=True)
    out = []
    for n in sizes:
        try:
            out.append(run_size(n, abi, bc))
            json.dump(out, open(os.path.join(HERE, "consortium_results.json"), "w"), indent=2)
        except Exception as e:
            print(f"  !! n={n} failed: {e}")
            subprocess.run("pkill -f 'geth --datadir' || true", shell=True)

    print(f"\n{'='*66}\n  SUMMARY — revocation propagation, Clique PoA, period={PERIOD}s\n{'='*66}")
    print(f"  {'nodes':>5} {'inclusion med':>14} {'propagation med':>16} {'prop p95':>10} {'total med':>11}")
    for r in out:
        print(f"  {r['nodes']:>5} {r['inclusion']['median_ms']:>11.0f} ms "
              f"{r['propagation']['median_ms']:>13.0f} ms {r['propagation']['p95_ms']:>7.0f} ms "
              f"{r['total']['median_ms']:>8.0f} ms")
    print("\n  wrote consortium_results.json")


if __name__ == "__main__":
    main()
