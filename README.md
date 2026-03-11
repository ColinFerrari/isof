# isof

Python reader and verifier for the **ISOF v1.0** format, an open standard for exchanging geochemical isotopic data.

This format allows exchanging in a single file the isotopic data along with all associated metadata (analytical methods used for each sample, purification yields, analysis pipeline...), while enabling traceability of modifications once files are produced and certifying the origin of the file (laboratory certification).

**Sovereignty and Confidentiality:** Signature verification is a 100% local process. No data is sent to a third-party server for validation.

Why use this parser?

   - **Trust by Design**: Instantly verify if a file has been modified after export (Level 1) or if it truly originates from a certified laboratory (Level 2).

   - **Data Integrity, Locally**: All signature checks are performed 100% offline. Your sensitive research data never leaves your machine.

   - **Science-Ready**: Go from a secure JSON document to a clean Pandas DataFrame in two lines of code, with built-in alerts for suspicious analytical yields.

```python
import isof

report = isof.load("analyse_bolivie.isof")

if report.is_authentic():
    print(f"Signed by: {report.signature.signed_by}")

df = report.to_pandas()
print(df[["sample_name", "element", "ratio", "ratio_2se"]])
```

The ISOF format is used by [IsoFind](https://isofind.tech), but this parser is independent and can read any file compliant with the [ISOF v1.0 specification](https://isofind.tech/isof-spec).

---

## Installation

```bash
pip install isof
```

With pandas support:

```bash
pip install isof[pandas]
```

Requires Python ≥ 3.9.

---

## Usage

### Load a file

```python
import isof

report = isof.load("analyse.isof")
print(report)
# <ISOfDocument v1.0 — 12 échantillon(s) — IGE Grenoble>
```

From a JSON string (API, database):

```python
with open("analyse.isof") as f:
    text = f.read()

report = isof.loads(text)
```

### Verify integrity

```python
# Simple check
if report.is_authentic():
    print("Data integrity confirmed")

# Detailed result
result = report.verify()
print(result.valid)      # bool
print(result.level)      # 1 (SHA-256) or 2 (IsoFind PKI)
print(result.signer)     # organisation or certificate CN
print(result.signed_at)  # ISO 8601 timestamp
print(result.reason)     # None if valid, error message otherwise
```

Two signature levels coexist in the format:

| Level | Mechanism                  | Guarantee                                                      |
| ----- | -------------------------- | -------------------------------------------------------------- |
| 1     | SHA-256 over the data      | Integrity, file has not been modified since export            |
| 2     | ECDSA P-256 + IsoFind PKI  | Authenticity, signed by a laboratory certified by IsoFind     |

Verification works **offline**: IsoFind certificates are embedded in the package.

### Access data

```python
# Sample list
for sample in report.samples:
    print(sample.id, sample.name, sample.classification)
    for iso in sample.isotope_data:
        print(f"  {iso.element} {iso.system} = {iso.ratio} ± {iso.ratio_2se}")

# Look up a sample by identifier
s = report.sample("BOL-24-01")

# Filter
sources = report.filter_samples(classification="source")
sb_samples = report.filter_samples(element="Sb")
combined = report.filter_samples(element="Pb", material_type="minerai")

# Metadata
print(report.created_by.organisation)
print(report.project.reference)
print(report.project.client)
```

### Purification yields

```python
# Yields for a sample
yields = report.yields_for_sample("BOL-24-01")
for y in yields:
    print(f"{y.element}: {y.value_pct}%")

# Contamination alerts (yield > 105%)
suspects = report.suspicious_yields()
for y in suspects:
    print(f"Possible contamination — {y.sample_id} / {y.element}: {y.value_pct}%")
```

### Methods and pipelines

```python
# Preparation methods
for key, method in report.methods.items():
    print(f"{key} — {method.name} ({method.type})")
    if method.yield_min_pct:
        print(f"  Expected yield: {method.yield_min_pct}–{method.yield_max_pct}%")

# Pipelines
for key, pipeline in report.pipelines.items():
    print(f"{pipeline.name} ({pipeline.element})")
    for stage in pipeline.stages:
        print(f"  {stage.order}. {stage.label}")
```

### Export to pandas

```python
df = report.to_pandas()

# One row per isotopic measurement, sample metadata included
df[["sample_name", "element", "ratio", "ratio_2se", "instrument"]]

# Standard pandas filtering
pb_data = df[df["element"] == "Pb"]
sources = df[df["classification"] == "source"]
```

### CSV export

```python
report.to_csv("export.csv")
# equivalent to report.to_pandas().to_csv("export.csv", index=False)
```

---

## Error handling

```python
from isof.exceptions import ISOfParseError, ISOfVersionError, ISOfSignatureError

try:
    report = isof.load("file.isof")
except ISOfVersionError as e:
    print(f"Version {e.found} not supported, please update python-isof")
except ISOfParseError as e:
    print(f"Invalid file: {e}")

# Corrupted vs. absent signature — two distinct cases
result = report.verify()
if result.level == 0:
    print("No signature in this file")
elif not result.valid:
    print(f"Signature present but invalid: {result.reason}")
```

---

## ISOF format

Structure of an `.isof` document (JSON):

```
{
  "isof_version": "1.0",
  "created_at": "2025-03-10T14:32:00Z",
  "created_by": { "software", "operator", "organisation" },
  "project": { "name", "reference", "client", "classification" },
  "samples": [ ... ],       ← isotopic data per sample
  "methods": { ... },       ← preparation protocols
  "pipelines": { ... },     ← method sequences per element
  "purification": { ... },  ← measured yields per (sample, element)
  "assignments": [ ... ],   ← method ↔ sample links
  "signature": { ... }      ← optional
}
```

Full specification: [isofind.tech/isof-spec](https://isofind.tech/isof-spec)

---

## Development

```bash
git clone https://github.com/ColinFerrari/isof
cd isof
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT, see [LICENSE](LICENSE).

This package is maintained by [Colin Ferrari](https://isofind.tech).
The ISOF format is an open standard — third-party contributions and implementations are welcome.
