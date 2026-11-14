# ADR 0002: MITRE ATT&CK Navigator Layer Synthesis

* **Status:** Accepted
* **Date:** 2026-11-15
* **Author:** Mohammad Hassan Jalal
* **Decision Makers:** Detection Architect, GRC Thesis Strategist

---

## 1. Context and Problem Statement

Security analysts and detection engineers require visual feedback demonstrating where their detection rules map within the MITRE ATT&CK Enterprise Matrix, and which specific tactics/techniques were triggered during an incident. Manually translating alerts into MITRE ATT&CK Navigator JSON layers is tedious, prone to schema errors, and unsuitable for automated CI/CD pipelines or real-time incident reports.

## 2. Decision Drivers

* **Specification Compliance:** Must strictly conform to MITRE ATT&CK Navigator v4.5 specification (`domain: "enterprise-attack"`).
* **Quantified Severity & Confidence Scoring:** Must map severity levels into standardized scores (Critical: 95, High: 80, Medium: 60, Low: 40) with confidence values.
* **Dual Export Capabilities:** Must support generating layers for both observed incident alerts and full detection rule coverage.

## 3. Considered Options

1. **Option 1: Static Web Dashboard Only:** Render MITRE tactic tables in the terminal using Rich.
2. **Option 2: Third-Party Navigator Python Library:** Introduce external dependency on unmaintained GitHub libraries.
3. **Option 3: Native Specification Exporter in `sentinel/engine.py`:** Standalone generator producing compliant Navigator v4.5 JSON layers with color gradients and metadata.

## 4. Decision Outcome

**Chosen Option: Option 3 (Native Specification Exporter)**

### Implementation:

`export_navigator_layer()` in `DetectionEngine` maps `techniqueID`, converts tactics to normalized lowercase slugs (`execution`, `initial-access`), applies hex color coding (`#ef4444`, `#f97316`), and embeds severity/confidence metadata.

## 5. Consequences

### Positive Consequences
* **Immediate Visual Triage:** The generated JSON can be dragged directly into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for executive presentation.
* **Zero External Dependencies:** Implemented using pure Python standard library `json` module.
* **Seamless CLI Integration:** Enabled via `--navigator <path>` flag across all CLI flows.
