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
twelve-point one. It cannot be merged into the published Chrome/Firefox/Apple/Linux panel as a
CVSS-weighted series, and its "mean base score" is a mean of one or two records wherever it is
defined at all. This is a property of the CISA-ADP container, not of the records: the CNA container
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
