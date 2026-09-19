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

Path: `containers.cna.metrics[].cvssV3_1.baseScore` (the vendor's own score). Printed only to show that the
2-of-2373 coverage above is a property of the CISA-ADP container, not of the records.

| month | n | rated | sum_base | mean_base |
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

