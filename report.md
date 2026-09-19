# report — listing-41, Microsoft CNA monthly series

**Artifact**: this directory. `extract.mjs` produces `table.md`; `LIMITS.md` is the required limits
section; `table.md` is the frozen output (sha256 `e34c63bb95b609aef1b47b4db25e14334366681ada9c9992eccd1c3c7dbbfe2b`).

## What I found

1. **The required CVSS source is nearly empty for this CNA.** Of 2,373 Microsoft-assigned records
   published 2025-09 .. 2026-08, **2** carry a CVSS base score in the CISA-ADP (Vulnrichment)
   container — **coverage 0.084%**, CVE-2026-21223 (5.1, 2026-01) and CVE-2026-32186 (9.8, 2026-04).
   The other 2,371 carry only an SSVC `other` object there. The CNA container, by contrast, carries a
   CVSS v3.1 base score in 2,372 of the same 2,373 records. The listing forbids substituting the
   vendor's score, so the required table is a two-point series and the vendor figures appear only as a
   clearly labelled diagnostic. This is the result the series exists to surface: the Microsoft panel
   cannot be built as a CVSS-weighted monthly series from this source.
2. **Every month is a Patch Tuesday dump.** 87.6% of records were published on a Tuesday; each month's
   modal day is its second Tuesday. The bucket measures Microsoft's release calendar, not discovery.
3. **July and August 2026 hold 47.2% of the window** (648 + 471 of 2,373), against 61–219 for the other
   ten months. Both peaks are second Tuesdays, so it is a genuine release-size surge.
4. **The records are silent on who found anything.** 0 of 2,373 carry `credits`, `source`, or a
   `timeline`. The only pointer out is `references` → the MSRC update-guide page, where credit lives
   outside the CVE record.
5. One record is `state: REJECTED` (CVE-2026-32187, 2026-03-27) and is included, with the deviation
   stated, because the predicate given does not filter state.

## Exact selection predicate

```
cveMetadata.assignerShortName === "microsoft"        // case-sensitive, exactly this string
&& UTC month of cveMetadata.datePublished in [2025-09 .. 2026-08]
```

Every distinct `assignerShortName` in the two year-trees matching `/micro/i`, with counts over the
full trees (`cves/2025` + `cves/2026`, 107,040 files):

| assignerShortName | records | vendor | included |
|---|---|---|---|
| `microsoft` | 4,205 | Microsoft Corporation | **yes** — the only Microsoft CNA |
| `trendmicro` | 58 | Trend Micro | no — different vendor |
| `Microchip` | 14 | Microchip Technology | no — different vendor |
| `Supermicro` | 11 | Super Micro Computer | **no — explicitly excluded** |
| `OMICRON` | 3 | OMICRON electronics | no — different vendor |

**Supermicro is excluded** because it is a different company (server hardware) with its own CNA; a
`/micro/i` match would have silently pulled in 86 non-Microsoft records. The selected name matches
`assignerOrgId f38d906d-7342-40ea-92c1-6c4a2c6478c8` in every selected record. 4,205 Microsoft
records exist in the two trees; 2,373 fall in the window, the rest outside it.

## Exact JSON path read for CVSS

```
containers.adp[]                     // filter: providerMetadata.shortName === "CISA-ADP"
  .metrics[]
  .cvssV3_1.baseScore                // number
containers.adp[].metrics[].cvssV4_0.baseScore   // fallback, only if v3.1 absent
```

Coverage, measured over the 2,373 window records:

| what | count | share |
|---|---|---|
| `metrics[].cvssV3_1.baseScore` present in CISA-ADP | 2 | 0.084% |
| `metrics[].cvssV4_0.baseScore` present in CISA-ADP | 0 | 0% |
| CISA-ADP `metrics[]` carrying only `other` (SSVC) | 2,371 | 99.9% |
| no CISA-ADP container at all | 1 (CVE-2026-32187) | — |

**v3.1 versus v4.0**: no record carries both in the CISA-ADP container — in fact no record carries
v4.0 there at all — so the fallback never fires and the choice of preference order cannot change the
table. Both scored records were confirmed individually by reading their files. A record with no base
score is counted as **unrated**, never as 0: `sum_base` is a sum over rated records only (0.0 when
none), and `mean_base` renders as `—` when `rated = 0` rather than as `0.00`.

## Anomalies and surprises

- The 2-of-2,373 coverage is the surprise, and it is a container-level fact rather than a data error:
  CISA's Vulnrichment program evidently enriches this CNA with SSVC decisions instead of CVSS.
- CVE-2026-32186 (the 9.8) and CVE-2026-32187 (the REJECTED, no-CVSS, no-ADP record) are adjacent
  CVE ids published a month apart — 32186 in April with a CISA-ADP CVSS, 32187 in March with none.
- 2,373 of 2,373 records have been revised since publication (`dateUpdated` month ≠ `datePublished`
  month), so the served record is not the record as first published.

## Exact commands run

```bash
# corpus (already cloned here; the commit is the one named in table.md)
git -C journal/raw-2026-09-19/earn/repos/cvelistV5 rev-parse HEAD
#   -> c56df66eb612fc6d8489d7b2b8a6dc8e7469bde6

# the deliverable, twice, and the comparison
cd journal/raw-2026-09-19/earn/listing-41
node extract.mjs --repo=../repos/cvelistV5 > run1.txt
node extract.mjs --repo=../repos/cvelistV5 > run2.txt
cmp run1.txt run2.txt      # byte-identical; sha256 e34c63bb95b609aef1b47b4db25e14334366681ada9c9992eccd1c3c7dbbfe2b
cp run1.txt table.md

# the diagnostics quoted above (scratch, since removed)
node scan-recon.mjs       # /micro/i assignerShortName enumeration
node scan-cvss.mjs        # CISA-ADP vs CNA coverage
node scan-deep.mjs        # per-container CVSS presence, scored records
node scan-days.mjs        # Patch Tuesday concentration, monthly volumes
node scan-credits.mjs     # credits / source / timeline availability
```

A stranger reproduces `table.md` with the four-line clone-and-checkout in `extract.mjs`'s header
followed by `node extract.mjs --repo=./cvelistV5 > table.md`. No credentials, no network at run time,
Node ≥ 18, built-ins only; the scan visits files in sorted order and emits no timestamps, so two runs
are byte-identical (verified).
