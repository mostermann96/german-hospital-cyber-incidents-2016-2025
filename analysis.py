#!/usr/bin/env python3
"""Analyse incidents.csv and locations.csv in their supplied export format. Python 3.10+."""
# SPDX-License-Identifier: MIT
import argparse
import csv
import hashlib
import json
import re
import statistics
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSION = "1.1.1"
KRITIS_CASE_THRESHOLD = 30000
GROUPS = ("overall", "kritis", "comparator")
TYPES = {
    "Ransomware": "ransomware_malware", "Malware": "ransomware_malware",
    "Infrastructure failure": "infrastructure", "Network Issues": "infrastructure",
    "Data breach": "data_breach", "Data breach / Physical Theft": "data_breach",
    "Data breach / Loss": "data_breach", "Phishing": "phishing",
    "Vulnerability": "vulnerability", "Hack": "vulnerability",
    "Insider threat": "insider", "DDoS": "denial_of_service",
    "DDoS / Attempted": "denial_of_service",
}
TIERS = {"diversion", "paper_or_analogue_fallback", "negligible_or_data_only",
         "other_disruption", "insufficient_information"}
FACTORS = {"second": 1/86400, "minute": 1/1440, "hour": 1/24,
           "day": 1, "week": 7, "month": 30}
MISSING = {"", "?", "na", "-"}
INCIDENT_FIELDS = {
    "incident_id", "year", "locations_reported", "incident_type_as_recorded",
    "entry_point_as_recorded", "diversion_as_recorded", "treatment_delay",
    "patient_harm_as_recorded", "containment_as_recorded", "recovery_as_recorded",
    "operational_tier", "tier_rationale", "reported_source", "supplementary_source",
}
LOCATION_FIELDS = {
    "location_id", "incident_id", "location", "inpatient_cases_recorded",
    "incident_year", "report_year_recorded",
}


def read_csv(path, keys, required=()):
    """Read UTF-8 comma/semicolon CSVs, optionally preceded by the file's title."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        header = handle.readline()
        if header.strip() == path.stem:
            start = handle.tell()
            header = handle.readline()
        else:
            start = 0
        delimiter = ";" if ";" in header else ","
        handle.seek(start)
        reader = csv.DictReader(handle, delimiter=delimiter, strict=True)
        fields = reader.fieldnames
        if not fields or any(not f.strip() for f in fields) or len(set(fields)) != len(fields):
            raise ValueError(f"Missing or duplicate column names: {path.name}")
        missing = (set(keys) | set(required)) - set(fields)
        if missing:
            raise ValueError(f"Missing columns in {path.name}: {', '.join(sorted(missing))}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"No data rows: {path.name}")
    seen = set()
    for row in rows:
        if None in row or any(v is None for v in row.values()):
            raise ValueError(f"Malformed CSV row: {path.name}")
        key = tuple(row.get(k, "") for k in keys)
        if any(not k for k in key) or key in seen:
            raise ValueError(f"Missing or duplicate key in {path.name}: {key}")
        seen.add(key)
    return rows


def write_csv(path, rows):
    if not rows:
        raise ValueError(f"No rows for {path.name}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def numeric_duration(raw):
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(second|minute|min|hour|h|day|week|month)s?",
                         raw.strip().lower())
    if not match:
        return None
    unit = {"min": "minute", "h": "hour"}.get(match[2], match[2])
    return float(match[1]) * FACTORS[unit]


def mapped_duration(raw):
    """Dated audit reconstruction; the returned rule is exported for every record."""
    s = raw.strip().lower()
    if s in MISSING:
        return None, "missing_as_recorded"
    value = numeric_duration(s)
    if value is not None:
        return value, "numerical_unit_conversion"
    rules = {
        "same day": (0.5, "same_day_or_night"),
        "same night": (0.5, "same_day_or_night"),
        "several days": (3., "several_days"),
        "weeks": (31., "unspecified_weeks"),
        "several weeks": (31., "unspecified_weeks"),
        "months": (90., "unspecified_months"),
        "weeks to months": (31., "weeks_to_months"),
        "none": (0., "none_as_zero"),
        "6+ weeks": (42., "lower_bound_as_boundary"),
        "< 1 week": (3.5, "less_than_week"),
        "< 12 hours": (0.5, "less_than_day_or_12h"),
        "< 1day": (0.5, "less_than_day_or_12h"),
        "< 1 day": (0.5, "less_than_day_or_12h"),
        "< 1 hour": (1/24, "less_than_hour"),
        "~1 week": (7., "approximate_week"),
        "2 days & 5 days": (2., "first_containment_interval"),
        "2 weeks / months for city": (14., "hospital_component"),
        "4 days ?": (4., "uncertain_numerical_value"),
        "about 5 days (e-mail to be restored 17 feb 2016)": (5., "projected_email_interval"),
        "same day (computers isolated immediately)": (0.5, "same_day_or_night"),
        "same day (blocked by antivirus); mail system cut 12 feb": (0.5, "same_day_or_night"),
        "several hours (mar 2016); ~5.5 hours (1 apr 2016, 20:00-01:30)": (5.5/24, "specified_containment_episode"),
    }
    if s not in rules:
        raise ValueError(f"Unreviewed duration wording: {raw!r}")
    return rules[s]


def entry_group(raw):
    s = raw.strip().lower()
    if s in {"", "?", "-"}:
        return "unknown_entry"
    if "e-mail" in s:
        return "email"
    if any(t in s for t in ("vulnerab", "citrix", "netscaler", "exchange")):
        return "internet_service"
    return "other_entry"


def load_data(root=ROOT):
    incidents = read_csv(root/"incidents.csv", ("incident_id",), INCIDENT_FIELDS)
    locations = read_csv(root/"locations.csv", ("location_id",), LOCATION_FIELDS)
    incident_ids = {r["incident_id"] for r in incidents}
    by_id = defaultdict(list)
    for row in locations:
        if row["incident_id"] not in incident_ids:
            raise ValueError(f"Location references an unknown incident: {row['location_id']}")
        if not re.fullmatch(r"[1-9][0-9]*", row["location_id"]):
            raise ValueError(f"Invalid location ID: {row['location_id']}")
        cases = row["inpatient_cases_recorded"]
        if cases and not re.fullmatch(r"[0-9]+", cases):
            raise ValueError(f"Invalid inpatient count: {row['location_id']}")
        row["kritis_volume_proxy"] = (
            "unknown" if not cases else "yes" if int(cases) >= KRITIS_CASE_THRESHOLD else "no"
        )
        by_id[row["incident_id"]].append(row)
    for row in incidents:
        iid = row["incident_id"]
        if not re.fullmatch(r"[1-9][0-9]*", iid) or not by_id[iid]:
            raise ValueError(f"Invalid incident ID or no location record: {iid}")
        if not re.fullmatch(r"[1-9][0-9]*", row["locations_reported"]):
            raise ValueError(f"Invalid affected-site count: {iid}")
        if row["incident_type_as_recorded"] not in TYPES:
            raise ValueError(f"Unknown incident category: {iid}")
        if row["treatment_delay"] not in {"yes", "no", "unknown"}:
            raise ValueError(f"Unknown treatment-delay category: {iid}")
        if row["patient_harm_as_recorded"] not in {"Yes", "No", "?", "-", ""}:
            raise ValueError(f"Unknown patient-harm category: {iid}")
        if row["diversion_as_recorded"] not in {"j", "n", "nA", "nA (but likely)", ""} and not re.fullmatch(r"j \(.+\)", row["diversion_as_recorded"]):
            raise ValueError(f"Unknown diversion category: {iid}")
        if row["operational_tier"] not in TIERS or not row["tier_rationale"]:
            raise ValueError(f"Missing severity coding or rationale: {iid}")
        diversion = row["diversion_as_recorded"].startswith("j")
        if diversion != (row["operational_tier"] == "diversion"):
            raise ValueError(f"Severity hierarchy disagrees with recorded diversion: {iid}")
        if not (row["reported_source"] or row["supplementary_source"]):
            raise ValueError(f"No source reference for incident {iid}")
        if not (row["year"].isdigit() and 2016 <= int(row["year"]) <= 2025) and row["year"] != "2016-2018":
            raise ValueError(f"Unsupported incident year: {iid}")
        for field in ("recovery_as_recorded", "containment_as_recorded"):
            mapped_duration(row[field])
        row["group"] = "kritis" if any(l["kritis_volume_proxy"] == "yes" for l in by_id[iid]) else "comparator"
        row["type"] = TYPES[row["incident_type_as_recorded"]]
        row["entry"] = entry_group(row["entry_point_as_recorded"])
    return incidents, locations


def summary(values):
    values = [x for x in values if x is not None]
    if not values:
        return dict(n=0, median=None, q1=None, q3=None, mean=None)
    quartiles = statistics.quantiles(values, n=4, method="inclusive") if len(values) > 1 else [None]*3
    return dict(n=len(values), median=statistics.median(values), q1=quartiles[0],
                q3=quartiles[2], mean=statistics.mean(values))


def calculate(incidents, locations):
    """Calculate solely from observations and coding rules; never read manuscript targets."""
    results, coding = {}, []
    groups = {g: [r for r in incidents if g == "overall" or r["group"] == g] for g in GROUPS}
    groups["ransomware"] = [r for r in incidents if r["incident_type_as_recorded"] == "Ransomware"]
    groups["infrastructure"] = [r for r in incidents if r["type"] == "infrastructure"]

    def count(key, n, denominator):
        results[key+".count"] = n
        results[key+".percent"] = 100*n/denominator if denominator else None

    for group, rows in groups.items():
        results[f"cohort.{group}.n"] = len(rows)
        for measure, field, parser in (
            ("recovery_mapped", "recovery_as_recorded", lambda x: mapped_duration(x)[0]),
            ("containment_mapped", "containment_as_recorded", lambda x: mapped_duration(x)[0]),
            ("recovery_numeric", "recovery_as_recorded", numeric_duration)):
            stats = summary([parser(r[field]) for r in rows])
            results.update({f"{measure}.{group}.{metric}": value for metric, value in stats.items()})
            results[f"{measure}.{group}.available_percent"] = 100*stats["n"]/len(rows) if rows else None
        if group not in GROUPS:
            continue
        for cat in dict.fromkeys(TYPES.values()):
            count(f"category.{cat}.{group}", sum(r["type"] == cat for r in rows), len(rows))
        for cat in ("email", "internet_service", "other_entry", "unknown_entry"):
            count(f"entry.{cat}.{group}", sum(r["entry"] == cat for r in rows), len(rows))
        outcomes = {
            "diversion": lambda r: r["diversion_as_recorded"].startswith("j"),
            "delay": lambda r: r["treatment_delay"] == "yes",
            "patient_safety": lambda r: r["patient_harm_as_recorded"] == "Yes",
            "diversion_or_delay": lambda r: r["diversion_as_recorded"].startswith("j") or r["treatment_delay"] == "yes",
            "paper_or_diversion": lambda r: r["operational_tier"] in {"diversion", "paper_or_analogue_fallback"},
        }
        for name, condition in outcomes.items():
            count(f"outcome.{name}.{group}", sum(condition(r) for r in rows), len(rows))
        for tier in sorted(TIERS):
            count(f"tier.{tier}.{group}", sum(r["operational_tier"] == tier for r in rows), len(rows))
    count("cohort.kritis", len(groups["kritis"]), len(incidents))
    count("category.ransomware_only.overall", len(groups["ransomware"]), len(incidents))
    results["sites.named_rows"] = sum(r["location"] not in ("", "?") for r in locations)
    results["sites.all_rows"] = len(locations)
    results["sites.reported_total"] = sum(int(r["locations_reported"]) for r in incidents)
    count("sites.kritis_named", sum(r["kritis_volume_proxy"] == "yes" and r["location"] not in ("", "?") for r in locations), results["sites.named_rows"])
    for name, condition in {"single": lambda n: n == 1, "two": lambda n: n == 2,
                            "three": lambda n: n == 3, "four_plus": lambda n: n >= 4,
                            "multi": lambda n: n > 1}.items():
        results[f"sites.{name}_incidents"] = sum(condition(int(r["locations_reported"])) for r in incidents)
    known = [r for r in incidents if r["treatment_delay"] != "unknown"]
    results["delay.known_n"] = len(known)
    results["delay.unknown_n"] = len(incidents)-len(known)
    count("delay.known", sum(r["treatment_delay"] == "yes" for r in known), len(known))
    for lo, hi in ((2016, 2018), (2019, 2021), (2022, 2025)):
        rows = [r for r in incidents if (r["year"].isdigit() and lo <= int(r["year"]) <= hi)
                or r["year"] == f"{lo}-{hi}"]
        prefix = f"period.{lo}_{hi}"
        results[prefix+".n"] = len(rows)
        count(prefix+".specified", sum(r["entry"] != "unknown_entry" for r in rows), len(rows))
        for route in ("email", "internet_service", "other_entry"):
            results[prefix+"."+route] = sum(r["entry"] == route for r in rows)
    dated = [r for r in incidents if r["year"].isdigit()]
    results["years.definite_n"] = len(dated)
    results["years.interval_n"] = len(incidents)-len(dated)
    for year in range(2016, 2026):
        rows = [r for r in dated if int(r["year"]) == year]
        results[f"annual.{year}.n"] = len(rows)
        count(f"annual.{year}.email", sum(r["entry"] == "email" for r in rows), len(rows))
    window = [r for r in dated if 2018 <= int(r["year"]) <= 2023]
    results["comparison.2018_2023.n"] = len(window)
    results["comparison.2018_2023.kritis_n"] = sum(r["group"] == "kritis" for r in window)
    for row in incidents:
        recovery, rec_rule = mapped_duration(row["recovery_as_recorded"])
        control, con_rule = mapped_duration(row["containment_as_recorded"])
        coding.append(dict(incident_id=row["incident_id"], kritis_group=row["group"],
            incident_group=row["type"], entry_group=row["entry"],
            recovery_as_recorded=row["recovery_as_recorded"], mapped_recovery_days=recovery,
            recovery_rule=rec_rule, containment_as_recorded=row["containment_as_recorded"],
            mapped_containment_days=control, containment_rule=con_rule,
            numerical_recovery_days=numeric_duration(row["recovery_as_recorded"]),
            operational_tier=row["operational_tier"], tier_rationale=row["tier_rationale"]))
    return results, coding


def table1(results):
    definitions = [("Ransomware and other malware", "category.ransomware_malware"),
        ("Phishing", "category.phishing"), ("Vulnerability exploit", "category.vulnerability"),
        ("Infrastructure failure", "category.infrastructure"), ("Data breach or physical theft", "category.data_breach"),
        ("Denial of service", "category.denial_of_service"), ("Insider threat", "category.insider"),
        ("Email attachment or link", "entry.email"), ("Internet-facing vulnerability or service", "entry.internet_service"),
        ("Other entry point", "entry.other_entry"), ("Unknown or not applicable entry point", "entry.unknown_entry"),
        ("Ambulance diversion", "outcome.diversion"), ("Surgery or treatment delayed", "outcome.delay"),
        ("Reported patient-safety impact", "outcome.patient_safety")]
    table = [{"characteristic": "Incidents: n", **{g: results[f"cohort.{g}.n"] for g in GROUPS}}]
    def display(key, group):
        percent = results[f"{key}.{group}.percent"]
        return f"{results[f'{key}.{group}.count']} ({percent:.1f}%)" if percent is not None else "0 (NA)"
    for label, key in definitions:
        table.append({"characteristic": label, **{g: display(key, g) for g in GROUPS}})
    for measure in ("recovery_mapped", "recovery_numeric", "containment_mapped"):
        for metric in ("n", "median", "q1", "q3", "mean"):
            table.append({"characteristic": f"{measure}: {metric}", **{g: results[f"{measure}.{g}.{metric}"] for g in GROUPS}})
    return table


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT,
                        help="Directory containing both CSVs (default: directory of this script)")
    parser.add_argument("--out", type=Path, default=Path("results"), help="New output directory; existing directories are never replaced")
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("Output already exists; choose a new --out directory")
    try:
        input_hashes = {name: hashlib.sha256((args.data_dir/name).read_bytes()).hexdigest()
                        for name in ("incidents.csv", "locations.csv")}
        incidents, locations = load_data(args.data_dir)
        calculated, coding = calculate(incidents, locations)
        location_coding = [{key: r[key] for key in (
            "location_id", "incident_id", "location", "inpatient_cases_recorded",
            "incident_year", "report_year_recorded", "kritis_volume_proxy")}
            for r in locations]
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=args.out.parent) as temporary:
            build = Path(temporary)/"output"
            build.mkdir()
            write_csv(build/"results.csv", [dict(result_id=k, value=v) for k, v in sorted(calculated.items())])
            write_csv(build/"table1.csv", table1(calculated))
            write_csv(build/"record_coding.csv", coding)
            write_csv(build/"location_coding.csv", location_coding)
            report = dict(analysis_version=VERSION, python_version=sys.version.split()[0],
                          incidents=len(incidents), location_rows=len(locations),
                          calculated_results=len(calculated), status="COMPLETED",
                          input_sha256=input_hashes,
                          analysis_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                          kritis_grouping=f"Any linked site with recorded inpatient cases >= {KRITIS_CASE_THRESHOLD}; volume proxy, not verified legal status",
                          duration_rules="Preserved from supplied analysis.py; see README.md and record_coding.csv")
            (build/"run_report.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
            build.rename(args.out)
        print(f"COMPLETED: {len(incidents)} incidents, {len(locations)} location rows; outputs: {args.out}")
        return 0
    except (ValueError, KeyError, OSError, csv.Error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
