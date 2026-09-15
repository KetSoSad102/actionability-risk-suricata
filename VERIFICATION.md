# Verification record

Verification date: 2026-09-06

Completed successfully in the build environment:

- Python bytecode compilation for `src/` and `tests/`.
- 15 unit/regression tests.
- Scoring of the bundled `logs/suricata/eve.json` fixture.
- 10/10 exact SID and revision metadata matches.
- 10/10 alerts matched `config/ground_truth.yaml`.
- Response-side SQLi, XSS, Nmap, and ColdFusion alerts resolved to the expected client/server roles.
- Criterion-level contributions summed to the reported Actionability and Risk totals.
- Payload success/failure indicators overrode HTTP-status-only inference as configured.
- Two-factor post-alert design generated 10 observed seeds, 50 base-context vignettes, and 500 presentations.
- Paired ablation, equal-weight and field-presence comparators, and 30 weight perturbations regenerated from source.
- Seven figures were regenerated in both PNG and PDF formats, including the context--profile heatmap.
- Figure export rejects empty or malformed PNG/PDF artifacts before replacing a valid file.
- The blinded annotation pack selected 300 items with exact context, profile, cell, and SID balance.
- Three empty rating slots per item produced 900 expected rating rows without fabricated analyst responses.
- The post-annotation analyzer was verified for agreement, AUPRC baselines, and `seed_id`-cluster bootstrap output.
- AIT-ADS conversion was verified on Wazuh-embedded Suricata fixtures without inventing absent flow, payload, or outcome evidence.
- YAML parsing for Compose, scoring, context/evidence variants, ground truth, and rule metadata.
- Shell syntax checking for all scripts.
- Compose configuration maps writable services to the invoking UID/GID; the Suricata image receives its documented `PUID`/`PGID` variables.
- All 16 bundled rule lines remain attributed to upstream commit `73d86b249635215f0dee05dc38a32d49c8b1810c`.

Docker and a Suricata binary were unavailable in the build environment, so PCAP regeneration and a fresh Suricata run were not executed here. The committed EVE fixture was used for the Python end-to-end regression. The full AIT-ADS corpus was not downloaded, and no analyst ratings were fabricated or reported. On a machine with Docker, run:

```bash
./scripts/run_all.sh
```

That command regenerates the PCAP and EVE output before scoring, ground-truth validation, the 500-presentation experiment, figures, and the empty annotation pack.

Generate only the post-alert experiment with:

```bash
./scripts/run_experiments.sh
```
