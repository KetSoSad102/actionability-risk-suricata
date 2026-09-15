# Labeled AIT-ADS pilot

This pilot runs the adapter on the smallest AIT-ADS scenario,
`russellmitchell`, and reports descriptive coverage rather than detection or
classification performance.

## Provenance

- Dataset: AIT Alert Data Set, Zenodo record 8263181,
  <https://doi.org/10.5281/zenodo.8263181>
- Dataset archive: `ait_ads.zip`, MD5
  `43db6b1f0996e0024befd617706c50e9`
- Phase intervals: `labels.csv`, MD5
  `60ff33796c77fd2136c4d1a4bc841bd9`
- Per-alert labels: `alerts_csv/russellmitchell_alerts.txt` from
  <https://github.com/ait-aecid/alert-data-set>, commit
  `ce927ddaeaa674f6909e1de676fa7dc293e393bd`
- Scenario input: `russellmitchell_wazuh.json`
- Adapter seed for the optional 25% archetype sample: `2026`

The per-alert file is required because the Zenodo `labels.csv` contains phase
intervals, while the adapter joins the official derived labels by whole-second
timestamp and normalized signature.

## Reproduction

After downloading and extracting the official files, run:

```bash
./scripts/import_ait_ads.sh \
  russellmitchell \
  /path/to/russellmitchell_wazuh.json \
  /path/to/alerts_csv/russellmitchell_alerts.txt
```

The original Wazuh export represents large Suricata flow identifiers as
integral decimal strings such as `114520921835946.000000`. The adapter parses
these exactly as integers; converting through a binary float could lose
identifier precision.

## Results

| Label group | Raw alerts | Archetypes | Role resolved | HTTP context | Decisive outcome | SID metadata | Archetype mean actionability |
|---|---:|---:|---:|---:|---:|---:|---:|
| Attack phase | 213 | 18 | 90.6% | 13.6% | 11.7% | 12.7% | 0.361 |
| False positive | 8,973 | 13 | 99.6% | 3.6% | 0.2% | 0.0% | 0.385 |
| All | 9,186 | 31 | 99.4% | 3.9% | 0.4% | 0.3% | 0.371 |

The input contained 41,488 Wazuh records. The adapter retained 9,186
Wazuh-embedded Suricata alerts, with no malformed records and no missing SIDs.
All retained alerts joined to an official time-phase label. The 213
attack-phase alerts cover `cracking`, `dnsteal`, `service_scan`, `webshell`,
and `wpscan`; the other 8,973 alerts are labeled `false_positive`.

All retained alerts preserve a `flow_id`, but the export provides neither
payload nor Community ID. Only 27 alerts, all SID 2024364, match the bundled
metadata catalog through explicit SID fallback; the external data carries a
different rule revision. Of 31 deterministic archetypes, 27 have unknown
outcome, two are possibly successful, and two contain failure evidence.

The similar actionability means for attack and false-positive archetypes are
not a failed classifier result: actionability measures evidence readiness,
not maliciousness. Raw alert frequencies are temporally dependent and are
reported only as descriptive coverage. Statistical comparisons should use
archetypes or demonstrably independent flows/incidents.
