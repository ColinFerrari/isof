# isof

Lecteur et vérificateur Python pour le format **ISOF v1.0 / v1.1 / v1.2** (**I**sotopic **S**ecure **O**pen **F**ormat), standard ouvert pour l'échange de données géochimiques et analytiques.

Le format ISOF permet d'échanger en un seul fichier :

- **Rapports isotopiques** avec métadonnées analytiques complètes (depuis v1.0)
- **Concentrations élémentaires** en unité pivot normalisée et unité d'origine (v1.2)
- **Paramètres physico-chimiques** comme pH, Eh, température (v1.2)
- **Molécules et ions dissous** avec conformité réglementaire (v1.2)
- Méthodes analytiques, pipelines et rendements de purification
- Traçabilité des modifications via signatures SHA-256 (niveau 1) ou ECDSA P-256 + PKI IsoFind (niveau 2)
- Chiffrement de bout en bout optionnel du contenu scientifique via X25519 + ChaCha20-Poly1305 (v1.2)

**Souveraineté et Confidentialité :** La vérification des signatures et le déchiffrement sont 100 % locaux. Aucune donnée n'est envoyée vers un serveur tiers.

```python
import isof

report = isof.load("analyse_bolivie.isof")

if report.is_authentic():
    print(f"Signé par : {report.signature.signed_by}")

df = report.to_pandas()
print(df[["sample_name", "element", "ratio", "ratio_2se"]])
```

Le format ISOF est utilisé par [IsoFind](https://isofind.tech), mais ce parser est indépendant et peut lire tout fichier conforme à la [spécification ISOF](https://isofind.tech/isof-spec).

---

## Installation

```bash
pip install isof
```

Avec support pandas :

```bash
pip install isof[pandas]
```

Requiert Python ≥ 3.9.

---

## Utilisation

### Charger un fichier

```python
import isof

report = isof.load("analyse.isof")
print(report)
# <ISOfDocument v1.2 — 12 échantillon(s) — IGE Grenoble>
```

Depuis une chaîne JSON (API, base de données) :

```python
with open("analyse.isof") as f:
    text = f.read()

report = isof.loads(text)
```

### Vérifier l'intégrité

```python
# Réponse simple
if report.is_authentic():
    print("Données intègres")

# Résultat détaillé
result = report.verify()
print(result.valid)      # bool
print(result.level)      # 1 (SHA-256) ou 2 (PKI IsoFind)
print(result.signer)     # organisation ou CN du certificat
print(result.signed_at)  # horodatage ISO 8601
print(result.reason)     # None si valide, message d'erreur sinon
```

Deux niveaux de signature coexistent dans le format :

| Niveau | Mécanisme                 | Garantie                                                    |
| ------ | ------------------------- | ----------------------------------------------------------- |
| 1      | SHA-256 sur les données   | Intégrité, fichier non modifié depuis l'export              |
| 2      | ECDSA P-256 + PKI IsoFind | Authenticité, signé par un laboratoire certifié par IsoFind |

La vérification fonctionne **hors-ligne** : les certificats IsoFind sont embarqués dans le package.

### Déchiffrer un fichier chiffré (v1.2)

ISOF v1.2 introduit le chiffrement optionnel de bout en bout du contenu scientifique. Un fichier peut rester lisible et sa signature vérifiable alors que samples, methods et rendements demeurent opaques tant que le destinataire ne déchiffre pas.

```python
report = isof.load("mission_defense.isof")

if report.is_encrypted:
    # L'enveloppe reste lisible (created_by, project, signature)
    # mais samples/methods/... sont des collections vides jusqu'au déchiffrement
    print("Contenu scientifique opaque, clé privée requise")
    priv_pem = open("ma_cle_privee.pem").read()
    report = report.decrypt(priv_pem)

# Après déchiffrement, utilisation classique du document
df = report.to_pandas()
```

Le chiffrement utilise une enveloppe hybride :

- X25519 ECDH enveloppe une clé de session aléatoire de 32 octets pour le destinataire
- ChaCha20-Poly1305 (ou AES-256-GCM) chiffre le payload scientifique canonicalisé
- HKDF-SHA256 avec le contexte `ISOF-v1.2-key-wrap` dérive la clé de wrapping

La clé privée peut être fournie en PEM PKCS#8, 32 octets raw, ou base64 des octets raw. Le chiffrement n'utilise aucun réseau, l'opération est entièrement locale.

### Accéder aux données

```python
# Liste des échantillons
for sample in report.samples:
    print(sample.id, sample.name, sample.classification)
    for iso in sample.isotope_data:
        print(f"  {iso.element} {iso.system} = {iso.ratio} ± {iso.ratio_2se}")
    for geo in sample.geochem_data:
        print(f"  {geo.element} : {geo.display_value} {geo.display_unit}")
    for phys in sample.physico_data:
        print(f"  {phys.parameter} = {phys.value}")
    for mol in sample.molecules_data:
        print(f"  {mol.nom} ({mol.cas}) : {mol.valeur} {mol.unite}")

# Chercher un échantillon par identifiant
s = report.sample("BOL-24-01")

# Chercher un paramètre physico-chimique
ph_record = s.physico_parameter("pH")
if ph_record and ph_record.value < 5.0:
    print("Eau acide")

# Filtrer — couvre les ratios isotopiques ET les concentrations géochim
sources    = report.filter_samples(classification="source")
sb_samples = report.filter_samples(element="Sb")
combined   = report.filter_samples(element="Pb", material_type="Ore")

# Alertes de conformité réglementaire (v1.2)
for sample, molecule in report.non_compliant_molecules():
    print(f"Alerte {sample.name} : {molecule.nom} dépasse "
          f"{molecule.seuil_ref} {molecule.seuil_ref_unit}")

# Métadonnées
print(report.created_by.organisation)
print(report.project.reference)
```

### Rendements de purification

```python
# Rendements d'un échantillon
yields = report.yields_for_sample("BOL-24-01")
for y in yields:
    print(f"{y.element} : {y.value_pct}%")

# Alertes contamination (rendement > 105 %)
suspects = report.suspicious_yields()
for y in suspects:
    print(f"Contamination possible — {y.sample_id} / {y.element} : {y.value_pct}%")
```

### Méthodes et pipelines

```python
# Méthodes de préparation
for key, method in report.methods.items():
    print(f"{key} — {method.name} ({method.type})")
    if method.yield_min_pct:
        print(f"  Rendement attendu : {method.yield_min_pct}–{method.yield_max_pct}%")

# Pipelines
for key, pipeline in report.pipelines.items():
    print(f"{pipeline.name} ({pipeline.element})")
    for stage in pipeline.stages:
        print(f"  {stage.order}. {stage.label}")
```

### Export vers pandas

L'export DataFrame prend désormais un paramètre `family` qui sélectionne la famille de mesures à aplatir :

```python
# Rapports isotopiques (défaut, comportement v1.0)
df = report.to_pandas()
# Une ligne par mesure isotopique
df[["sample_name", "element", "ratio", "ratio_2se", "instrument"]]

# Concentrations élémentaires (v1.2)
df_geo = report.to_pandas(family="geochem")
df_geo[["sample_name", "element", "value_normalized", "display_value", "display_unit"]]

# Paramètres physico-chimiques (v1.2)
df_phys = report.to_pandas(family="physico")
df_phys[["sample_name", "parameter", "value", "uncertainty", "method"]]

# Molécules dissoutes (v1.2)
df_mol = report.to_pandas(family="molecules")
df_mol[["sample_name", "nom", "cas", "valeur", "unite", "conforme"]]

# Filtrage pandas standard
pb_data = df[df["element"] == "Pb"]
sources = df[df["classification"] == "source"]
alertes = df_mol[df_mol["conforme"] == False]
```

### Export CSV

```python
report.to_csv("isotopes.csv")                       # famille par défaut
report.to_csv("geochem.csv",   family="geochem")
report.to_csv("physico.csv",   family="physico")
report.to_csv("molecules.csv", family="molecules")
```

---

## Gestion des erreurs

```python
from isof.exceptions import (
    ISOfParseError, ISOfVersionError,
    ISOfSignatureError, ISOfEncryptionError,
)

try:
    report = isof.load("fichier.isof")
except ISOfVersionError as e:
    print(f"Version {e.found} non supportée, mettez isof à jour")
except ISOfParseError as e:
    print(f"Fichier invalide : {e}")

# Signature corrompue vs. absente — deux cas distincts
result = report.verify()
if result.level == 0:
    print("Pas de signature dans ce fichier")
elif not result.valid:
    print(f"Signature présente mais invalide : {result.reason}")

# Erreurs de déchiffrement
try:
    clear = report.decrypt(ma_cle_privee_pem)
except ISOfEncryptionError as e:
    print(f"Échec du déchiffrement : {e}")
```

---

## Format ISOF

Structure d'un document `.isof` (JSON) :

```
{
  "isof_version": "1.2",
  "created_at": "2025-03-10T14:32:00Z",
  "created_by": { "software", "operator", "organisation" },
  "project": { "name", "reference", "client", "classification" },
  "samples": [ {
      "id", "name", "matrix", ...,
      "isotope_data":   [ ... ],  ← v1.0+
      "geochem_data":   [ ... ],  ← v1.2, optionnel
      "physico_data":   [ ... ],  ← v1.2, optionnel
      "molecules_data": [ ... ]   ← v1.2, optionnel
  } ],
  "methods": { ... },
  "pipelines": { ... },
  "purification": { ... },
  "assignments": [ ... ],
  "signature": { ... },          ← optionnel
  "encryption": { ... }          ← optionnel, v1.2
}
```

Spécification complète : [isofind.tech/isof-spec](https://isofind.tech/isof-spec)

---

## Développement

```bash
git clone https://github.com/ColinFerrari/isof
cd isof
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Licence

MIT, voir [LICENSE](LICENSE).

Ce package est maintenu par [Colin Ferrari](https://isofind.tech).
Le format ISOF est un standard ouvert, contributions et implémentations tierces bienvenues.
