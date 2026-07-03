# isof

Python reader, verifier, signer and builder for the **ISOF v1.0 / v1.1 / v1.2 / v1.3** (**I**sotopic **S**ecure **O**pen **F**ormat) format, an open standard for exchanging geochemical and analytical data.

The ISOF format allows exchanging in a single file:

- **Isotopic ratios** with full analytical metadata (since v1.0)
- **Elemental concentrations** with normalized and original units (v1.2)
- **Physicochemistry parameters** such as pH, Eh, temperature (v1.2)
- **Dissolved molecules and ions** with regulatory compliance (v1.2)
- Analytical methods, pipelines and purification yields
- Traceable modifications through SHA-256 (level 1) or ECDSA P-256 + IsoFind PKI (level 2) signatures
- Optional end-to-end encryption of the scientific payload via X25519 + ChaCha20-Poly1305 (v1.2)

**Sovereignty and Confidentiality:** Signature verification and decryption are 100% local. No data is sent to a third-party server.

```python
import isof

report = isof.load("analyse_bolivie.isof")

if report.is_authentic():
    print(f"Signed by: {report.signature.signed_by}")

df = report.to_pandas()
print(df[["sample_name", "element", "ratio", "ratio_2se"]])
```

The ISOF format is used by [IsoFind](https://isofind.tech), but this parser is independent and can read any file compliant with the [ISOF specification](https://isofind.tech/isof-spec).

---

## Installation

```bash
py -m pip install isof
```

With pandas support:

```bash
py -m pip install isof[pandas]
```

Requires Python ≥ 3.9.

---

## Usage

### Load a file

```python
import isof

report = isof.load("analyse.isof")
print(report)
# <ISOfDocument v1.2, 12 échantillon(s), IGE Grenoble>
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

| Level | Mechanism                 | Guarantee                                                 |
| ----- | ------------------------- | --------------------------------------------------------- |
| 1     | SHA-256 over the data     | Integrity, file has not been modified since export        |
| 2     | ECDSA P-256 + IsoFind PKI | Authenticity, signed by a laboratory certified by IsoFind |

Verification works **offline**: IsoFind certificates are embedded in the package.

### Sign a document

The package can also produce signed artefacts. Signing keys are never held by
the package: the caller supplies their own private key and certificate, and the
private key never leaves the caller's machine (only the public certificate is
embedded in the artefact).

```python
import isof

# Level 2 (ECDSA P-256): requires the caller's key and certificate.
isof.sign_file(
    "analysis_unsigned.isof",
    "analysis_signed.isof",
    level=2,
    signed_by="My Laboratory",
    key_path="lab_key.pem",
    cert_path="lab_cert.pem",
    issuing_cert_path="issuing_ca.pem",  # optional, embeds the Issuing CA
)

# Level 1 (SHA-256): integrity only, no key needed.
signed = isof.sign_document(document, level=1, signed_by="My Laboratory")
```

A certificate issued under the IsoFind PKI is accepted by any recipient that
trusts the embedded IsoFind root. A self-issued certificate produces a
cryptographically valid signature, accepted by a recipient who adds that root to
their trust anchors, which is the model for test PKIs and sovereign deployments.

### Build a document

The package can assemble a document from raw data, giving a full path from data
to signed artefact. The builder fabricates nothing: a field that is not supplied
stays `null`, never filled with a default or guessed value. Only the technical
scaffolding (format version, creation timestamp, empty data families) is filled
in automatically.

```python
import isof

iso = isof.make_isotope(element="Sb", system="123Sb/121Sb", ratio=0.46, ratio_2se=0.02)
geo = isof.make_geochem(element="Sb", value_normalized=7824, display_unit="ug/L", method="ICP-MS")
sample = isof.make_sample("OR-01", name="Oruro 1", matrix="water",
                          isotope_data=[iso], geochem_data=[geo])

document = isof.new_document([sample], created_by={"software": "my-script"})
signed = isof.sign_document(document, level=2, signed_by="My Laboratory",
                            key_path="lab_key.pem", cert_path="lab_cert.pem")
```

Only `id` is required for a sample. A record missing its meaning-bearing field
(`system`, `element`, `parameter`, `nom`) raises a warning rather than an error,
since a file may legitimately share only some data families. An unknown field is
dropped with a warning, so a typo cannot silently create a signed field.

### Decrypt an encrypted file (v1.2)

ISOF v1.2 introduces optional end-to-end encryption of the scientific payload. A file may be readable and signature-verifiable while its samples, methods and yields remain opaque until the intended recipient decrypts it.

```python
report = isof.load("mission_defense.isof")

if report.is_encrypted:
    # The envelope remains readable (created_by, project, signature)
    # but samples/methods/... are empty collections until decryption
    print("Opaque scientific payload, private key required")
    priv_pem = open("my_private_key.pem").read()
    report = report.decrypt(priv_pem)

# After decryption, use the document as usual
df = report.to_pandas()
```

The encryption uses a hybrid envelope:

- X25519 ECDH wraps a random 32-byte session key for the recipient
- ChaCha20-Poly1305 (or AES-256-GCM) encrypts the canonicalized scientific payload
- HKDF-SHA256 with context `ISOF-v1.2-key-wrap` derives the wrapping key

The private key may be provided as PEM PKCS#8, raw 32 bytes, or base64 of the raw bytes. Encryption uses no network: the entire operation is local.

### Access data

```python
# Sample list
for sample in report.samples:
    print(sample.id, sample.name, sample.classification)
    for iso in sample.isotope_data:
        print(f"  {iso.element} {iso.system} = {iso.ratio} ± {iso.ratio_2se}")
    for geo in sample.geochem_data:
        print(f"  {geo.element}: {geo.display_value} {geo.display_unit}")
    for phys in sample.physico_data:
        print(f"  {phys.parameter} = {phys.value}")
    for mol in sample.molecules_data:
        print(f"  {mol.nom} ({mol.cas}): {mol.valeur} {mol.unite}")

# Look up a sample by identifier
s = report.sample("BOL-24-01")

# Look up a physicochemistry parameter
ph_record = s.physico_parameter("pH")
if ph_record and ph_record.value < 5.0:
    print("Acidic water")

# Filter, covers isotope ratios and geochem concentrations
sources   = report.filter_samples(classification="source")
sb_samples = report.filter_samples(element="Sb")
combined  = report.filter_samples(element="Pb", material_type="Ore")

# Regulatory alerts (v1.2)
for sample, molecule in report.non_compliant_molecules():
    print(f"Alert {sample.name}: {molecule.nom} exceeds "
          f"{molecule.seuil_ref} {molecule.seuil_ref_unit}")

# Metadata
print(report.created_by.organisation)
print(report.project.reference)
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
    print(f"Possible contamination, {y.sample_id} / {y.element}: {y.value_pct}%")
```

### Methods and pipelines

```python
# Preparation methods
for key, method in report.methods.items():
    print(f"{key}: {method.name} ({method.type})")
    if method.yield_min_pct:
        print(f"  Expected yield: {method.yield_min_pct}–{method.yield_max_pct}%")

# Pipelines
for key, pipeline in report.pipelines.items():
    print(f"{pipeline.name} ({pipeline.element})")
    for stage in pipeline.stages:
        print(f"  {stage.order}. {stage.label}")
```

### Export to pandas

The DataFrame export now takes a `family` parameter that selects which measurement family to flatten:

```python
# Isotope ratios (default, v1.0 behavior)
df = report.to_pandas()
# One row per isotopic measurement
df[["sample_name", "element", "ratio", "ratio_2se", "instrument"]]

# Elemental concentrations (v1.2)
df_geo = report.to_pandas(family="geochem")
df_geo[["sample_name", "element", "value_normalized", "display_value", "display_unit"]]

# Physicochemistry parameters (v1.2)
df_phys = report.to_pandas(family="physico")
df_phys[["sample_name", "parameter", "value", "uncertainty", "method"]]

# Dissolved molecules (v1.2)
df_mol = report.to_pandas(family="molecules")
df_mol[["sample_name", "nom", "cas", "valeur", "unite", "conforme"]]

# Standard pandas filtering
pb_data = df[df["element"] == "Pb"]
sources = df[df["classification"] == "source"]
alerts  = df_mol[df_mol["conforme"] == False]
```

### CSV export

```python
report.to_csv("isotopes.csv")                       # default family
report.to_csv("geochem.csv",   family="geochem")
report.to_csv("physico.csv",   family="physico")
report.to_csv("molecules.csv", family="molecules")
```

---

## Error handling

```python
from isof.exceptions import (
    ISOfParseError, ISOfVersionError,
    ISOfSignatureError, ISOfEncryptionError,
)

try:
    report = isof.load("file.isof")
except ISOfVersionError as e:
    print(f"Version {e.found} not supported, please update isof")
except ISOfParseError as e:
    print(f"Invalid file: {e}")

# Corrupted vs absent signature, two distinct cases
result = report.verify()
if result.level == 0:
    print("No signature in this file")
elif not result.valid:
    print(f"Signature present but invalid: {result.reason}")

# Decryption errors
try:
    clear = report.decrypt(my_private_key_pem)
except ISOfEncryptionError as e:
    print(f"Decryption failed: {e}")
```

---

## ISOF format

Structure of an `.isof` document (JSON):

```
{
  "isof_version": "1.2",
  "created_at": "2025-03-10T14:32:00Z",
  "created_by": { "software", "operator", "organisation" },
  "project": { "name", "reference", "client", "classification" },
  "samples": [ {
      "id", "name", "matrix", ...,
      "isotope_data":   [ ... ],  ← v1.0+
      "geochem_data":   [ ... ],  ← v1.2, optional
      "physico_data":   [ ... ],  ← v1.2, optional
      "molecules_data": [ ... ]   ← v1.2, optional
  } ],
  "methods": { ... },
  "pipelines": { ... },
  "purification": { ... },
  "assignments": [ ... ],
  "signature": { ... },          ← optional
  "encryption": { ... }          ← optional, v1.2
}
```

Full specification: [isofind.tech/isof-spec](https://isofind.tech/isof-spec)

---

## Development

```bash
git clone https://github.com/ColinFerrari/isof
cd isof
py -m pip install -e ".[dev]"
py -m pytest tests/ -v
```

---

## License

MIT, see [LICENSE](LICENSE).

This package is maintained by [Colin Ferrari](https://isofind.tech).
The ISOF format is an open standard, third-party contributions and implementations are welcome.
