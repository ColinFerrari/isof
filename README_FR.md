# isof

Lecteur et vérificateur Python pour le format **ISOF v1.0** (**IS**otopic **O**pen **F**ormat), standard ouvert pour l'échange de données isotopiques géochimiques.

Ce format permet d'échanger en un seul fichier les données isotopiques, ainsi que toutes les métadonnées qui y sont associées (méthodes analytiques utilisées pour chaque échantillon, rendements de purification, pipeline d'analyse...) tout en permettant une traçabilité sur les modifications des fichiers une fois produits et en permettant de certifier l'origine du fichier (certification par laboratoire).

**Souveraineté et Confidentialité :** La vérification des signatures est un processus 100% local. Aucune donnée n'est envoyée vers un serveur tiers pour validation.

```python
import isof

report = isof.load("analyse_bolivie.isof")

if report.is_authentic():
    print(f"Signé par : {report.signature.signed_by}")

df = report.to_pandas()
print(df[["sample_name", "element", "ratio", "ratio_2se"]])
```

Le format ISOF est utilisé par [IsoFind](https://isofind.tech), mais ce parser est indépendant et peut lire tout fichier conforme à la [spécification ISOF v1.0](https://isofind.tech/isof-spec).

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
# <ISOfDocument v1.0 - 12 échantillon(s) - IGE Grenoble>
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

### Accéder aux données

```python
# Liste des échantillons
for sample in report.samples:
    print(sample.id, sample.name, sample.classification)
    for iso in sample.isotope_data:
        print(f"  {iso.element} {iso.system} = {iso.ratio} ± {iso.ratio_2se}")

# Chercher un échantillon par identifiant
s = report.sample("BOL-24-01")

# Filtrer
sources = report.filter_samples(classification="source")
sb_samples = report.filter_samples(element="Sb")
combined = report.filter_samples(element="Pb", material_type="minerai")

# Métadonnées
print(report.created_by.organisation)
print(report.project.reference)
print(report.project.client)
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
    print(f"Contamination possible - {y.sample_id} / {y.element} : {y.value_pct}%")
```

### Méthodes et pipelines

```python
# Méthodes de préparation
for key, method in report.methods.items():
    print(f"{key} - {method.name} ({method.type})")
    if method.yield_min_pct:
        print(f"  Rendement attendu : {method.yield_min_pct}–{method.yield_max_pct}%")

# Pipelines
for key, pipeline in report.pipelines.items():
    print(f"{pipeline.name} ({pipeline.element})")
    for stage in pipeline.stages:
        print(f"  {stage.order}. {stage.label}")
```

### Export vers pandas

```python
df = report.to_pandas()

# Une ligne par mesure isotopique, métadonnées échantillon incluses
df[["sample_name", "element", "ratio", "ratio_2se", "instrument"]]

# Filtrage pandas standard
pb_data = df[df["element"] == "Pb"]
sources = df[df["classification"] == "source"]
```

### Export CSV

```python
report.to_csv("export.csv")
# équivalent à report.to_pandas().to_csv("export.csv", index=False)
```

---

## Gestion des erreurs

```python
from isof.exceptions import ISOfParseError, ISOfVersionError, ISOfSignatureError

try:
    report = isof.load("fichier.isof")
except ISOfVersionError as e:
    print(f"Version {e.found} non supportée, mettez python-isof à jour")
except ISOfParseError as e:
    print(f"Fichier invalide : {e}")

# Signature corrompue vs. absente - deux cas distincts
result = report.verify()
if result.level == 0:
    print("Pas de signature dans ce fichier")
elif not result.valid:
    print(f"Signature présente mais invalide : {result.reason}")
```

---

## Format ISOF

Structure d'un document `.isof` (JSON) :

```
{
  "isof_version": "1.0",
  "created_at": "2025-03-10T14:32:00Z",
  "created_by": { "software", "operator", "organisation" },
  "project": { "name", "reference", "client", "classification" },
  "samples": [ ... ],       ← données isotopiques par échantillon
  "methods": { ... },       ← protocoles de préparation
  "pipelines": { ... },     ← séquences de méthodes par élément
  "purification": { ... },  ← rendements mesurés par (échantillon, élément)
  "assignments": [ ... ],   ← liens méthode ↔ échantillon
  "signature": { ... }      ← optionnel
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
