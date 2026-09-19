# listing-41 — the Microsoft CNA monthly series, and the finding that the required source is nearly empty

One artifact a stranger re-runs without credentials. extract.mjs produces the table below from
CVEProject/cvelistV5 at a named commit; LIMITS.md is the condition's LIMITS section; report.md is the
working note. table.md is the raw frozen output of extract.mjs, committed so that "the re-run
reproduces the submitted table exactly" has a literal target to diff against.

Exact command line, from an empty directory:

    git clone --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
    cd cvelistV5 && git sparse-checkout set cves/2025 cves/2026 && git checkout c56df66eb612fc6d8489d7b2b8a6dc8e7469bde6 && cd ..
    node extract.mjs --repo=./cvelistV5 > table.md

# listing-41 — Microsoft CNA monthly series, 2025-09 .. 2026-08

Source: CVEProject/cvelistV5 at commit `c56df66eb612fc6d8489d7b2b8a6dc8e7469bde6` (cves/2025 + cves/2026, sparse).
Selection: `cveMetadata.assignerShortName === "microsoft"` (case-sensitive; excludes trendmicro, Supermicro, Microchip, OMICRON).
Window: UTC month of `cveMetadata.datePublished`, inclusive 2025-09 .. 2026-08. Records: 2373.
Files scanned: 107040 (parse failures: 0; total microsoft-assigned records in the two year trees: 4205).

Record states in the window: PUBLISHED=2372, REJECTED=1  — included, not dropped: CVE-2026-32187 (REJECTED, published 2026-03-27) (the predicate below is the listing's, which does not filter state)
Records whose month(dateUpdated) differs from month(datePublished): 2373 of 2373 — this is a snapshot of a revised corpus, not a live series.

## REQUIRED TABLE — CVSS base score from the CISA-ADP (Vulnrichment) container

Path read: `containers.adp[]` where `providerMetadata.shortName === "CISA-ADP"` then `metrics[].cvssV3_1.baseScore`
(`metrics[].cvssV4_0.baseScore` only where v4.0 is present and v3.1 is not). Unrated records are excluded from
sum and mean; they are never counted as zero.

| month | n | rated | sum_base | mean_base |
|---|---|---|---|---|
| 2025-09 | 94 | 0 | 0.0 | — |
| 2025-10 | 180 | 0 | 0.0 | — |
| 2025-11 | 71 | 0 | 0.0 | — |
| 2025-12 | 65 | 0 | 0.0 | — |
| 2026-01 | 125 | 1 | 5.1 | 5.10 |
| 2026-02 | 61 | 0 | 0.0 | — |
| 2026-03 | 97 | 0 | 0.0 | — |
| 2026-04 | 181 | 1 | 9.8 | 9.80 |
| 2026-05 | 161 | 0 | 0.0 | — |
| 2026-06 | 219 | 0 | 0.0 | — |
| 2026-07 | 648 | 0 | 0.0 | — |
| 2026-08 | 471 | 0 | 0.0 | — |
| **total** | **2373** | **2** | **14.9** | **7.45** |

Overall coverage (rated / n): 0.08% (2 of 2373)
Records with no CISA-ADP container at all: 1   Scored records: CVE-2026-21223 2026-01 cvssV3_1 5.1; CVE-2026-32186 2026-04 cvssV3_1 9.8

## DIAGNOSTIC — same records, CVSS from the CNA container (NOT the required source, not a substitute)

Column names below are prefixed cna_ so that no reader can mistake this table for the required one above.

Path: `containers.cna.metrics[].cvssV3_1.baseScore` (the vendor's own score). Printed only to show that the
2-of-2373 coverage above is a property of the CISA-ADP container, not of the records.

| month | n | cna_rated | cna_sum | cna_mean |
|---|---|---|---|---|
| 2025-09 | 94 | 94 | 682.5 | 7.26 |
| 2025-10 | 180 | 180 | 1291.5 | 7.17 |
| 2025-11 | 71 | 71 | 529.0 | 7.45 |
| 2025-12 | 65 | 65 | 494.9 | 7.61 |
| 2026-01 | 125 | 125 | 901.3 | 7.21 |
| 2026-02 | 61 | 61 | 451.5 | 7.40 |
| 2026-03 | 97 | 96 | 735.8 | 7.66 |
| 2026-04 | 181 | 181 | 1335.1 | 7.38 |
| 2026-05 | 161 | 161 | 1247.0 | 7.75 |
| 2026-06 | 219 | 219 | 1591.0 | 7.26 |
| 2026-07 | 648 | 648 | 4783.7 | 7.38 |
| 2026-08 | 471 | 471 | 3472.6 | 7.37 |
| **total** | **2373** | **2372** | **17515.9** | **7.38** |



---

# LIMITS — listing-41 Microsoft panel

Five limits, each with the measurement that establishes it. The first is the one that decides what
this artifact can be used for; the rest bound how the numbers may be read.

## 1. The required CVSS source is nearly empty for this CNA — 2 scored records out of 2,373

The listing requires CVSS to be read from the CISA-ADP "Vulnrichment" ADP container inside each
record. In the window 2025-09 .. 2026-08 that container carries a numeric CVSS base score in
**2 of 2,373** Microsoft records (0.084%). The other 2,371 carry only an `other` object there —
`metrics[].other.type = "ssvc"`, a CISA Coordinator SSVC decision, not a score. One record
(CVE-2026-32187) has no CISA-ADP container at all.

**Consequence.** The required table is a two-point series (2026-01: 5.1, 2026-04: 9.8), not a
twelve-point one. What **can** be merged into the published Chrome/Firefox/Apple/Linux panel is the
column this listing also requires and which is complete for every one of the twelve months: **n per
month** (94, 180, 71, 65, 125, 61, 97, 181, 161, 219, 648, 471), together with the coverage finding
itself — that the container the protocol names scores 2 of 2,373 records while the CNA container
scores 2,372 of the same 2,373. The CVSS-weighted column is the part that cannot be merged, and its
"mean base score" is a mean of one or two records wherever it is defined at all. This is a property of the CISA-ADP container, not of the records: the CNA container
carries a CVSS v3.1 base score in 2,372 of the same 2,373 records. That score is the vendor's own
and the listing forbids substituting it, so it is reported separately as a labelled diagnostic and
is **not** the table above it.

## 2. The monthly bucket measures release policy, not discovery

2,079 of 2,373 records (87.6%) were published on a Tuesday, and each month's modal publication day
is that month's **second Tuesday** — Patch Tuesday: 2025-09-09 (80 of 94, 85%), 2025-10-14 (167 of
180, 93%), 2025-11-11 (63 of 71, 89%), 2025-12-09 (56 of 65, 86%), 2026-01-13 (112 of 125, 90%),
2026-02-10 (54 of 61, 89%), 2026-03-10 (78 of 97, 80%), 2026-04-14 (163 of 181, 90%), 2026-05-12
(125 of 161, 78%), 2026-06-09 (200 of 219, 91%), 2026-07-14 (570 of 648, 88%), 2026-08-11 (402 of
471, 85%). A record's `datePublished` is the day Microsoft shipped the advisory. A vulnerability
found in month N and fixed in month N+2 is counted in N+2. Any reading of this series as discovery
rate, backlog, or responsiveness needs an external discovery date, which this repository does not
carry.

## 3. Two months hold 47% of the window

2026-07 (648 records) and 2026-08 (471) together hold 1,119 of 2,373 records (47.2%), against a
61–219 range for the other ten months. Both peaks are still second Tuesdays, so this is a
release-size surge rather than a backfill or a re-dating. A twelve-month mean over this window is
therefore not a level: it is dominated by the last two months, and any growth statement drawn from
it is a statement about July and August 2026.

## 4. These records say nothing about who found the vulnerability

**0 of 2,373** records carry `containers.cna.credits` (not even an empty array), `containers.cna.source`,
or a non-empty `containers.cna.timeline`. Reserving a CVE, publishing it, and updating it is the whole
of what this CNA writes. The only outbound pointer is `containers.cna.references` (2,372 records),
which is the Microsoft Security Response Center update-guide page for that CVE
(`https://msrc.microsoft.com/update-guide/vulnerability/CVE-…`). Finder credit lives there, outside
the CVE record and outside this repository, and is not retrievable from cvelistV5 at any commit. A
"who found it" column cannot be built from this source.

## 5. A snapshot of a revised corpus, and one rejected record is inside the count

Every one of the 2,373 records has a `dateUpdated` month different from its `datePublished` month:
the corpus serves post-revision content, and re-running against a later commit will not reproduce
these numbers even though the month buckets stay fixed. Separately, 1 of the 2,373 is
`state: REJECTED` — CVE-2026-32187, published 2026-03-27, the same record that has no CVSS and no
CISA-ADP container. It is **included** because the listing's predicate ("CVE records assigned by the
Microsoft CNA", bucketed by `datePublished`) does not filter state; dropping it silently would be an
unstated deviation. A reader who wants the PUBLISHED-only series should subtract 1 from 2026-03.


## 6. Arithmetic and formatting, so a hand-checker is not surprised

Sums are computed in IEEE-754 doubles and printed with toFixed(1); means are sum/rated and printed
with toFixed(2). One place where that differs from hand-rounding in the DIAGNOSTIC table: 1291.5/180
is 7.175 in decimal, which binary floating point holds just below, so toFixed(2) prints **7.17**
where hand-rounding gives 7.18. The required table is unaffected (its only defined mean is
14.9/2 = 7.45). The re-run is byte-identical, so this is a formatting note, not a reproduction risk.
