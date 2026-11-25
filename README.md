---
title: German hospital cybersecurity incident analysis
---

# German hospital cybersecurity incidents, 2016–2025

This package analyses the supplied [incidents.csv](incidents.csv) and
[locations.csv](locations.csv) for *A decade of digital vulnerability:
cybersecurity incidents in German hospitals from 2016–2025*. It contains
94 incident records and 203 linked incident-location records. The CSVs are
unchanged. Analysis version: 1.1.0 (21 November 2026).

## Run the analysis

Use Python 3.10 or later (tested with Python 3.11).

Keep `analysis.py`, `incidents.csv` and `locations.csv` in the same directory.
From that directory, run:

```sh
python analysis.py --out results
python -m unittest discover -s tests -v
```

On systems where Python is called `python3`, substitute `python3` for `python`.
To read CSVs from another directory:

```sh
python analysis.py --data-dir "path/to/data" --out results
```

Inputs default to the script's directory, regardless of the working directory.
The output path is relative to the current working directory. An existing output
directory is never overwritten; choose another name for a subsequent run.
Exit code 0 means the analysis completed; code 2 indicates an input or execution
error. Completion does not establish agreement with a manuscript or verify the
underlying incident reports.

| Output | Contents |
| --- | --- |
| `results.csv` | All calculated counts, percentages and duration summaries, identified by `result_id`. |
| `table1.csv` | Counts and whole-group percentages, plus mapped and numerical duration summaries for overall, KRITIS-proxy and comparator groups. |
| `record_coding.csv` | Incident groupings, original duration wording, converted values in days and conversion-rule identifiers. |
| `location_coding.csv` | Recorded inpatient volumes and report years, with the derived site-level KRITIS volume proxy. |
| `run_report.json` | Script/Python versions, input and script SHA-256 hashes, record counts and analysis limitations. |

Outputs use UTF-8 and comma delimiters. Empty numeric output cells indicate
unavailable values, not zero. Quartiles are left empty for a one-entry subset.
No figures are generated. There is no manuscript target file or recovery-endpoint
review table in these inputs, so the script neither compares manuscript values nor
calculates counts of source-confirmed completed recovery. It does not require a
manifest, workbook, manuscript or other absent release files.

## Data format and interpretation

The supplied CSVs are UTF-8, semicolon-delimited exports. Their first line is a
one-field title (`incidents` or `locations`); the second line contains column names.
The loader also accepts UTF-8 with a BOM, files without the title line, and
comma-delimited files. It checks required columns, unique IDs, row widths,
incident-location joins and the categorical values used in the analysis. It fails
on unrecognised duration wording rather than assigning a duration silently.

| Field or fields | Meaning and use |
| --- | --- |
| `incident_id` | Incident key shared by both CSVs. |
| `location_id` | Incident-location row key, retained from the original workbook row; not a persistent hospital ID. |
| `year` | Incident year or the recorded interval `2016-2018`. |
| `locations_reported` | Reported affected-site count for an incident. |
| `incident_type_as_recorded`, `entry_point_as_recorded` | Recorded text grouped by the explicit rules in `analysis.py`. |
| `diversion_as_recorded` | `j` and the qualified `j (...)` entry count as positive; other recorded values do not. |
| `treatment_delay` | `yes`, `no` or `unknown`; unknown values remain distinguishable. |
| `patient_harm_as_recorded` | Only `Yes` counts as a positive report; `No`, `?`, `-` and empty values are retained. |
| `operational_tier`, `tier_rationale` | Supplied severity coding and its rationale; positive diversion takes precedence. |
| `containment_as_recorded`, `recovery_as_recorded` | Original duration descriptions; blank, `?`, `nA` and `-` are missing. |
| `inpatient_cases_recorded`, `report_year_recorded`, `incident_year` | Recorded site volume and year information used to document the volume-based grouping. Blank volume is unknown. |
| `reported_source`, `supplementary_source`, `source_review_note` | Incident source references and any recorded review issues. |

There are 202 named incident-location observations and one placeholder for two
unidentified hospitals. A hospital may recur across incidents.

The CSVs do not contain KRITIS flags. The script derives a **volume proxy**: a site
meets the threshold if its recorded annual inpatient count is at least 30,000; an
incident enters the `kritis` group if any linked site meets it. The `comparator`
group includes incidents with no identified site meeting the threshold, including
the unidentified-site incident. This gives 29 and 65 incidents, respectively.

Categorical percentages use the whole group denominator, including unknown
outcomes. Treatment delay has 27 yes, 42 no and 25 unknown records: 27/94 = 28.7%
overall, compared with 27/69 = 39.1% among records with known delay coding. A
non-positive code is not necessarily evidence that an outcome did not occur.

Annual counts exclude the four incidents dated only to `2016-2018`; these remain
in the overall analysis and the 2016–2018 grouped period. Annual counts therefore
sum to 90, while the complete dataset contains 94 incidents.

## Duration rules

The supplied script's duration parsers are retained. The numerical subset accepts
only a single number followed by seconds, minutes (`min`), hours (`h`), days,
weeks or months, including the singular forms. Seconds, minutes and hours are
divided by 86,400, 1,440 and 24. Weeks use 7 days and months use 30 days.
Qualified, bounded or compound descriptions are excluded from that subset.
`4 days` in incident 46 is included as supplied. This yields **29 numerical
recovery entries**, median 3.0 days, IQR 0.75–11.00 days and mean 24.5 days.
Numerical wording does not demonstrate that restoration was completed.

Mapped durations additionally use the following explicit approximations, preserved
from the input script. Matching ignores case and outer whitespace.

| Recorded description | Mapped days |
| --- | ---: |
| `Same day`, `Same night` | 0.5 |
| `Several days` | 3 |
| `Weeks`, `Several weeks`, `Weeks to months` | 31 |
| `Months` | 90 |
| `None` | 0 |
| `6+ weeks` | 42 |
| `< 1 week` | 3.5 |
| `< 12 hours`, `< 1day`, `< 1 day` | 0.5 |
| `< 1 hour` | 1/24 |
| `~1 week` | 7 |
| `2 days & 5 days` | 2 (first interval) |
| `2 weeks / months for city` | 14 (hospital component) |
| `4 days ?` | 4 |
| `about 5 days (e-mail to be restored 17 Feb 2016)` | 5 (forecast) |
| `same day (computers isolated immediately)` | 0.5 |
| `same day (blocked by antivirus); mail system cut 12 Feb` | 0.5 |
| `several hours (Mar 2016); ~5.5 hours (1 Apr 2016, 20:00-01:30)` | 5.5/24 |

Missing durations are excluded from duration summaries. Quartiles use Python's
`statistics.quantiles(..., method="inclusive")`; calculations retain unrounded
precision. Mapped recovery has 64 observations, median 3.0 days, IQR 0.5–31.0
days and mean 20.0 days. These are descriptive summaries under the stated coding,
not verified times to complete restoration.



## Citation and license

Suggested attribution: Ostermann M, Goeldner M, Zimmermann M, Ghafur S, Freyer O,
Gilbert S. *A decade of digital vulnerability: cybersecurity incidents in German
hospitals from 2016–2025*. Accompanying dataset and analysis, version 1.1.0,
21 November 2026. Add the published article and repository release identifier
when available; no publication DOI is assigned here.

Python code, tests and documentation are licensed under the **MIT License**;
see [LICENSE](LICENSE). The incident and location data and analytical coding are
licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**;
see [LICENSE-DATA.txt](LICENSE-DATA.txt). These retain the licensing choices in
the supplied README. Preserve attribution and source provenance, and identify
changes to derivative data. Linked third-party reports retain their own rights;
these licenses do not cover those reports or the manuscript and figures.
