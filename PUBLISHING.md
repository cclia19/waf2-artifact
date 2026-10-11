# Publishing this artefact and minting the DOI

*This file is for the authors. Delete it before publishing, or leave it — it harms nothing.*

The Reproducibility Statement in the manuscript has one placeholder left:

> released at *[repository URL and DOI — author action required]*

Here is how to fill it. Two routes; the first takes about five minutes and gives you a DOI that updates with each release.

---

## Before you start: one decision

`LICENSE` is MIT and `README.md` says results are CC BY 4.0. **That is a default, not a legal determination.** Work funded under FRGS/1/2021/ICT07/UTAR/02/3 may be subject to UTAR intellectual-property policy and MoHE grant conditions. Confirm with the UTAR research office and change `LICENSE`, `CITATION.cff` and `.zenodo.json` if required. All three must agree.

---

## Route A — GitHub + Zenodo (recommended)

Gives you a permanent DOI, a browsable repository reviewers can read without downloading, and a new DOI automatically on every future release.

**1. Create the repository and push.**

From inside this directory, with the GitHub CLI authenticated as whichever account should own it:

```bash
gh auth login                       # if not already
gh repo create waf2-artifact --public --source=. --remote=origin --push
```

Or without the CLI: create an empty public repository on github.com, then

```bash
git remote add origin https://github.com/<user-or-org>/waf2-artifact.git
git branch -M main
git push -u origin main
```

**2. Switch on Zenodo for the repository.**

Go to <https://zenodo.org>, sign in **with GitHub**, open <https://zenodo.org/account/settings/github/>, find `waf2-artifact` in the list and flip its toggle **on**. This authorises Zenodo to watch the repository. Nothing is archived yet.

**3. Cut a release.**

```bash
git tag -a v1.0.0 -m "Artefact accompanying the WAF-2 manuscript"
git push origin v1.0.0
gh release create v1.0.0 --title "v1.0.0" --notes "Artefact accompanying the WAF-2 manuscript."
```

Zenodo picks up the release within a minute or two and mints a DOI. `.zenodo.json` in this directory supplies the title, authors, affiliations, keywords and description automatically, so there is nothing to type in.

**4. Take both DOIs.**

Zenodo gives you two: a **concept DOI** that always resolves to the newest version, and a **version DOI** fixed to v1.0.0. Cite the concept DOI in the paper — it stays correct if you release a v1.1.

**5. Fill the placeholder.** In the manuscript's Reproducibility Statement, replace

> *[repository URL and DOI — author action required]*

with, for example:

> `https://github.com/<user-or-org>/waf2-artifact` (archived at `https://doi.org/10.5281/zenodo.XXXXXXX`)

---

## Route B — Zenodo only, no GitHub

If you would rather not host the code on GitHub.

1. Go to <https://zenodo.org/uploads/new>.
2. Upload `waf2-artifact.zip`.
3. Set **Upload type** to *Software*.
4. Copy the title, description, authors, affiliations and keywords from `.zenodo.json` in this directory.
5. Set the licence to match your decision above.
6. Under *Funding*, search for the Ministry of Higher Education, Malaysia and attach grant **FRGS/1/2021/ICT07/UTAR/02/3** if it is listed; otherwise leave the acknowledgement in the description.
7. Publish. The DOI appears immediately.

You can also use <https://figshare.com> or your institutional repository; any of them satisfies a journal's data-availability requirement. Zenodo is the usual choice because it is free, permanent, CERN-operated, and integrates with GitHub.

---

## What reviewers will check

Worth running once yourself before you publish, because it is exactly what a thorough reviewer does:

```bash
pip install -r requirements.txt
./reproduce.sh gas          # must match results/gas_results.json exactly
./reproduce.sh proverif     # must match Table II
```

The gas benchmark is deterministic by design, so a mismatch means the contract changed. The consortium benchmark needs geth v1.13.x and about fifteen minutes; its absolute timings will differ on other hardware, but the ratios should not.

---

## A note on the journal submission itself

Publishing the artefact is independent of submitting the paper, and should come first so the DOI can go in the manuscript. The submission itself has to be done from your own account — pick the venue, create the submission, upload the manuscript and the cover letter. Nothing in this directory needs to go to the journal except the URL and DOI.
