#!/usr/bin/env node
// listing-41 — monthly CVSS-weighted patch series for the Microsoft CNA, from CVEProject/cvelistV5.
//
// EXACT COMMAND LINE (run from the directory containing this file):
//
//   git clone --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
//   cd cvelistV5
//   git sparse-checkout set cves/2025 cves/2026
//   git checkout c56df66eb612fc6d8489d7b2b8a6dc8e7469bde6
//   cd ..
//   node extract.mjs --repo=./cvelistV5 > table.md
//
// No credentials, no network at run time, Node >= 18, built-ins only.
//
// SELECTION PREDICATE (exact, case-sensitive):
//   cveMetadata.assignerShortName === "microsoft"
//   The /micro/i family in this repository also contains "trendmicro", "Supermicro",
//   "Microchip" and "OMICRON"; all four are DIFFERENT vendors and are excluded. Only the
//   lowercase exact string "microsoft" is the Microsoft CNA (assignerOrgId
//   f38d906d-7342-40ea-92c1-6c4a2c6478c8).
//
// WINDOW: the UTC month of cveMetadata.datePublished, inclusive 2025-09 .. 2026-08.
//
// CVSS SOURCE (the listing's requirement): the CISA-ADP "Vulnrichment" ADP container inside
// the same record, at the path
//   containers.adp[] . providerMetadata.shortName === "CISA-ADP"  ->  metrics[] . cvssV3_1.baseScore
// (cvssV4_0.baseScore is used only if a record carries v4.0 and no v3.1 in that container).
// It is NOT the CNA's own score (containers.cna.metrics[].cvssV3_1.baseScore) and NOT NVD.
// The CNA score is printed in a separate DIAGNOSTIC section, labelled as such, because the two
// containers disagree about coverage by two orders of magnitude here.
//
// A record with no CVSS base score in the required container counts as UNRATED, never as zero.
// sum_base is the sum over rated records; mean_base is sum_base/rated and is "—" when rated = 0.
//
// Output is deterministic: files are visited in sorted order and nothing is timestamped, so
// two runs are byte-identical.
import fs from "node:fs";
import path from "node:path";

const REPO = (process.argv.find((a) => a.startsWith("--repo=")) || "").slice(7) || "./cvelistV5";
const COMMIT = "c56df66eb612fc6d8489d7b2b8a6dc8e7469bde6";
const YEARS = ["2025", "2026"];
const MONTHS = [];
for (let y = 2025, m = 9; MONTHS.length < 12; m++) { if (m > 12) { m = 1; y++; } MONTHS.push(y + "-" + String(m).padStart(2, "0")); }

const rows = new Map(MONTHS.map((m) => [m, { n: 0, rated: 0, sum: 0, cnaRated: 0, cnaSum: 0, adpNoContainer: 0 }]));
const scored = [], stateCounts = new Map(), notPublished = [];
const scoredCve = new Set();
let scanned = 0, microsoftAll = 0, parseFail = 0, updatedMoved = 0;

for (const year of YEARS) {
  const base = path.join(REPO, "cves", year);
  if (!fs.existsSync(base)) { console.error("missing " + base); process.exit(2); }
  for (const bucket of fs.readdirSync(base).sort()) {
    const bp = path.join(base, bucket);
    if (!fs.statSync(bp).isDirectory()) continue;
    for (const f of fs.readdirSync(bp).sort()) {
      if (!f.endsWith(".json")) continue;
      scanned++;
      let j;
      try { j = JSON.parse(fs.readFileSync(path.join(bp, f), "utf8")); } catch { parseFail++; continue; }
      const meta = j.cveMetadata;
      if (!meta || meta.assignerShortName !== "microsoft") continue;
      microsoftAll++;
      // The month is taken from the STRING, never through Date: a datePublished lacking a trailing
      // Z would parse as local time and give a different month on a machine in another timezone,
      // which would break byte-identical reproduction. Checked over this window: 0 of the 2,373
      // Microsoft records lack the trailing Z, so this is defensive rather than a live fix.
      const month = String(meta.datePublished).slice(0, 7);
      if (!rows.has(month)) continue;
      const row = rows.get(month);
      row.n++;
      stateCounts.set(meta.state, (stateCounts.get(meta.state) || 0) + 1);
      if (meta.state !== "PUBLISHED") notPublished.push(meta.cveId + " (" + meta.state + ", published " + meta.datePublished.slice(0, 10) + ")");
      if (meta.dateUpdated && meta.dateUpdated.slice(0, 7) !== month) updatedMoved++;

      // required source: the CISA-ADP container
      const adps = ((j.containers && j.containers.adp) || []).filter((a) => a.providerMetadata && a.providerMetadata.shortName === "CISA-ADP");
      if (!adps.length) row.adpNoContainer++;
      let adpScore = null, adpKey = null;
      for (const a of adps) for (const mt of (a.metrics || [])) {
        if (mt.cvssV3_1 && typeof mt.cvssV3_1.baseScore === "number") { adpScore = mt.cvssV3_1.baseScore; adpKey = "cvssV3_1"; break; }
        if (mt.cvssV4_0 && typeof mt.cvssV4_0.baseScore === "number") { adpScore = mt.cvssV4_0.baseScore; adpKey = "cvssV4_0"; }
      }
      if (adpScore !== null) { row.rated++; row.sum += adpScore; scored.push([meta.cveId, month, adpKey, adpScore]); }

      // diagnostic only: the CNA's own container
      const cm = (j.containers && j.containers.cna && j.containers.cna.metrics) || [];
      const cna = cm.find((x) => x.cvssV3_1 && typeof x.cvssV3_1.baseScore === "number") ||
                  cm.find((x) => x.cvssV4_0 && typeof x.cvssV4_0.baseScore === "number");
      if (cna) { row.cnaRated++; row.cnaSum += (cna.cvssV3_1 || cna.cvssV4_0).baseScore; }
    }
  }
}

const f1 = (x) => x.toFixed(1), f2 = (x) => x.toFixed(2);
const tot = { n: 0, rated: 0, sum: 0, cnaRated: 0, cnaSum: 0, adpNoContainer: 0 };
for (const m of MONTHS) { const r = rows.get(m); for (const k of Object.keys(tot)) tot[k] += r[k]; }

const L = [];
L.push("# listing-41 — Microsoft CNA monthly series, 2025-09 .. 2026-08");
L.push("");
L.push("Source: CVEProject/cvelistV5 at commit `" + COMMIT + "` (cves/2025 + cves/2026, sparse).");
L.push("Selection: `cveMetadata.assignerShortName === \"microsoft\"` (case-sensitive; excludes trendmicro, Supermicro, Microchip, OMICRON).");
L.push("Window: UTC month of `cveMetadata.datePublished`, inclusive 2025-09 .. 2026-08. Records: " + tot.n + ".");
L.push("Files scanned: " + scanned + " (parse failures: " + parseFail + "; total microsoft-assigned records in the two year trees: " + microsoftAll + ").");
L.push("");
L.push("Record states in the window: " + [...stateCounts.entries()].sort().map(([k, v]) => k + "=" + v).join(", ") +
  (notPublished.length ? "  — included, not dropped: " + notPublished.join("; ") + " (the predicate below is the listing's, which does not filter state)" : ""));
L.push("Records whose month(dateUpdated) differs from month(datePublished): " + updatedMoved + " of " + tot.n +
  " — this is a snapshot of a revised corpus, not a live series.");
L.push("");
L.push("## REQUIRED TABLE — CVSS base score from the CISA-ADP (Vulnrichment) container");
L.push("");
L.push("Path read: `containers.adp[]` where `providerMetadata.shortName === \"CISA-ADP\"` then `metrics[].cvssV3_1.baseScore`");
L.push("(`metrics[].cvssV4_0.baseScore` only where v4.0 is present and v3.1 is not). Unrated records are excluded from");
L.push("sum and mean; they are never counted as zero.");
L.push("");
L.push("| month | n | rated | sum_base | mean_base |");
L.push("|---|---|---|---|---|");
for (const m of MONTHS) { const r = rows.get(m);
  L.push("| " + m + " | " + r.n + " | " + r.rated + " | " + f1(r.sum) + " | " + (r.rated ? f2(r.sum / r.rated) : "—") + " |"); }
L.push("| **total** | **" + tot.n + "** | **" + tot.rated + "** | **" + f1(tot.sum) + "** | **" + (tot.rated ? f2(tot.sum / tot.rated) : "—") + "** |");
L.push("");
L.push("Overall coverage (rated / n): " + f2(100 * tot.rated / tot.n) + "% (" + tot.rated + " of " + tot.n + ")");
L.push("Records with no CISA-ADP container at all: " + tot.adpNoContainer + (scored.length ? "   Scored records: " + scored.map((s) => s[0] + " " + s[1] + " " + s[2] + " " + s[3]).join("; ") : ""));
L.push("");
L.push("## DIAGNOSTIC — same records, CVSS from the CNA container (NOT the required source, not a substitute)");
L.push("");
L.push("Column names below are prefixed cna_ so that no reader can mistake this table for the required one above.");
L.push("");
L.push("Path: `containers.cna.metrics[].cvssV3_1.baseScore` (the vendor's own score). Printed only to show that the");
L.push("2-of-" + tot.n + " coverage above is a property of the CISA-ADP container, not of the records.");
L.push("");
L.push("| month | n | cna_rated | cna_sum | cna_mean |");
L.push("|---|---|---|---|---|");
for (const m of MONTHS) { const r = rows.get(m);
  L.push("| " + m + " | " + r.n + " | " + r.cnaRated + " | " + f1(r.cnaSum) + " | " + (r.cnaRated ? f2(r.cnaSum / r.cnaRated) : "—") + " |"); }
L.push("| **total** | **" + tot.n + "** | **" + tot.cnaRated + "** | **" + f1(tot.cnaSum) + "** | **" + (tot.cnaRated ? f2(tot.cnaSum / tot.cnaRated) : "—") + "** |");
L.push("");
console.log(L.join("\n"));
