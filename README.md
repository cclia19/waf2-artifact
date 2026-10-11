# WAF-2 — Research Artefact

Reproducibility artefact for **"A Consortium-Ledger Trust Registry for Cross-Domain Wi-Fi Roaming: Design, Formal Analysis, and Measured Cost."**

Yichiet Aun, Miao Xuan Ng, Shuaib Ahmed Wadho
Faculty of Information & Communication Technology, Universiti Tunku Abdul Rahman (UTAR), Kampar, Malaysia

---

## What this is

WAF-2 is a permissioned consortium-ledger **trust registry** for cross-domain Wi-Fi roaming. The design decision that matters is one of layering: the ledger is an *authorisation oracle*, not an authentication channel. Authentication remains unmodified IEEE 802.1X/EAP-TLS, the PMK is the first 256 bits of the EAP MSK (RFC 5247 §1.2), and the 802.11i four-way handshake is untouched — so link-layer confidentiality is preserved rather than traded away.

This repository contains everything needed to reproduce every number in the paper.

## What a reviewer can verify here

| Claim in the paper | Reproduced by |
|---|---|
| Table III, Table IV — on-chain gas, and the 52.3× / 2.5× revocation result | `analysis/gas_bench.py` |
| Table II, §VI-B, §VI-C, §VI-D — all formal security results | `proverif/*.pv` |
| Table V, Figure 1 — revocation propagation on a live 4–13 node consortium | `harness/consortium_bench.py` + `analysis/consortium_analysis.py` |

Both benchmarks are **deterministic**. The gas benchmark derives credential tags from a fixed seed, because EVM gas depends on calldata byte values and a benchmark using random tags is not reproducible at the precision gas is normally quoted. Re-running it reproduces the published figures exactly.

Each ProVerif model includes an explicit **non-vacuity check** — a query asserting that the honest protocol run is reachable. A model in which the honest run is unreachable verifies every safety property trivially and proves nothing, so we make that visible rather than silent.

We publish `proverif/waf2_malicious_member.pv`, which **fails by design**: a device roaming onto a malicious consortium member shares link-layer keys with it. This is inherent to every link-layer roaming federation and the OpenRoaming specification carries the equivalent caveat. The model shows the failure is *contained* — server-side injective agreement, credential-nonce secrecy and the authorisation property all still hold.

## Layout

```
contracts/WAFRegistry.sol        Consortium registry: membership, issuance, 3 revocation paths
proverif/waf2_core.pv            Secrecy, authorisation, injective agreement vs. a malicious member
proverif/waf2_fs.pv              Forward secrecy after every long-term key is leaked
proverif/waf2_kci.pv             Key-compromise-impersonation resistance
proverif/waf2_revocation.pv      Revocation enforced under total device compromise
proverif/waf2_malicious_member.pv  Inherent limitation (expected to fail; see above)
analysis/gas_bench.py            Functional tests + deterministic gas measurement
harness/consortium_bench.py      Stands up n-node Clique chains, measures revocation propagation
analysis/consortium_analysis.py  Statistics and Figure 1
results/                         Published outputs, for comparison against your own run
reproduce.sh                     Runs everything
```

## Requirements

- **Python 3.10+** — `pip install -r requirements.txt`
- **solc 0.8.24** — installed automatically by `py-solc-x` on first run
- **ProVerif 2.05** — https://bblanche.gitlabpages.inria.fr/proverif/ (requires OCaml; `./build` in the source tree)
- **go-ethereum v1.13.x** — **not v1.14 or later.** Clique proof-of-authority was removed in v1.14.0 (24 April 2024), and v1.14+ cannot act as a Clique signer. We used v1.13.15.

The consortium benchmark starts *n* geth processes on one host. 8 GB of RAM is comfortable up to 13 nodes.

## Running it

```bash
pip install -r requirements.txt
./reproduce.sh                     # everything
./reproduce.sh gas                 # Tables III-IV only (fast, ~30 s)
./reproduce.sh proverif            # Table II and §VI (~2 min)
./reproduce.sh consortium          # Table V and Figure 1 (~15 min; starts geth nodes)
```

## Two things that will bite you if you modify the contract

Both are real constraints of permissioned Ethereum-family chains, documented in §V of the paper:

1. **Compile with `evm_version=paris`.** solc 0.8.24 targets Shanghai by default and emits the `PUSH0` opcode. A Clique chain is pre-Shanghai and *cannot* enable Shanghai, because that fork requires the withdrawals field Clique does not produce. A Shanghai-targeted build fails at construction with no useful error.

2. **Confirm state changes; do not trust a receipt.** Clique reorganises freshly sealed blocks under signer contention and can drop the transaction with it. A transaction can return a successful receipt and then cease to have happened. `consortium_bench.py` re-submits until the expected state change is observable.

## Expected results

Revocation propagation, 20 revocations per consortium size, 600 per-node observations, Clique block period 2 s:

| Nodes | Inclusion (median) | Propagation (median) | p95 | End-to-end (median) |
|---|---|---|---|---|
| 4 | 3,975 ms | 13.8 ms | 23 ms | 3,995 ms |
| 7 | 3,929 ms | 23.9 ms | 97 ms | 3,974 ms |
| 10 | 3,416 ms | 34.9 ms | 574 ms | 3,990 ms |
| 13 | 3,926 ms | 42.2 ms | 77 ms | 4,004 ms |

The headline result is in the ratio, not the absolute numbers: **dissemination accounts for 0.3–1.1% of end-to-end revocation latency.** The rest is the consensus block period, which shows no significant dependence on consortium size (*p* = 0.68). A deployment needing faster revocation should shorten the block period or adopt an immediate-finality engine such as IBFT 2.0 — not limit how many venues may join.

Propagation grows at roughly 3.2 ms per access point (*R*² = 0.99) over the measured range. We report that slope only within 4–13 nodes and do not extrapolate.

**Timing figures will differ on your hardware.** Absolute latency depends on CPU, block period and host load. The ratios and the absence of a size dependence should hold. Gas figures and ProVerif results are exact and must match.

## Known limitations of this artefact

Stated here as plainly as in the paper, because an artefact that oversells itself is worse than none.

- **The consortium runs on a single host over loopback.** Propagation figures are a **lower bound**. A consortium spanning venues on different networks will be dominated by inter-site round-trip time, not by the few milliseconds per node measured here.
- **Thirteen nodes is not a large consortium**, and the host has two cores, so at the top end the signers contend for CPU in a way that one-node-per-venue would not.
- **The authentication plane is not here.** The `hostapd`/EAP-TLS integration described in §IV-A is specified in the paper but was not built or evaluated. Every security property in Table II is proved of the *abstract* protocol of §IV-C, not of its EAP-TLS composition. §VI-E states this gap explicitly.
- **ProVerif tables are not attacker-writable**, so the modelled malicious member holds a membership key but cannot invoke on-chain issuance or bulk revocation. Those entry points are defended by access control in the contract — issuer-derived tags and per-issuer bitmap namespacing, both covered by tests in `gas_bench.py` — not by the symbolic model.

## Citation

See `CITATION.cff`. Please cite the paper rather than this repository where possible.

## Licence

Code and models: MIT (`LICENSE`). Results and documentation: CC BY 4.0.

> **Authors: confirm this before publishing.** The licence is a default choice, not a legal determination. Work funded under FRGS/1/2021/ICT07/UTAR/02/3 may be subject to UTAR intellectual-property policy and MoHE grant conditions. Check with the UTAR research office and change this section if required.

## Acknowledgment

Supported by the Ministry of Higher Education (MoHE) Malaysia through the Fundamental Research Grant Scheme, FRGS/1/2021/ICT07/UTAR/02/3.
